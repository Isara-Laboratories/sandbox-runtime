/*
 * Seccomp BPF filter generator for Linux Unix socket policy
 *
 * Block mode denies socket(AF_UNIX). Allowlist mode permits Unix stream socket
 * creation, denies other Unix socket types, and sends connect() to a USER_NOTIF
 * supervisor for exact-path validation and safe emulation.
 *
 * The filter is exported in a format compatible with bubblewrap's --seccomp flag.
 *
 * SECURITY LIMITATION - 32-bit x86 (ia32):
 * TODO: This filter does NOT block socketcall() syscall, which is a security issue
 * on 32-bit x86 systems. On ia32, the socket() syscall doesn't exist - instead,
 * all socket operations are multiplexed through socketcall():
 *   - socketcall(SYS_SOCKET, [AF_UNIX, ...]) - can bypass this filter
 *   - socketcall(SYS_SOCKETPAIR, [AF_UNIX, ...]) - can bypass this filter
 *
 * To fix this, we need to add conditional rules that:
 * 1. Check if socketcall() exists on the current architecture (32-bit x86 only)
 * 2. Block socketcall(SYS_SOCKET, ...) when first arg of sub-call is AF_UNIX
 * 3. Block socketcall(SYS_SOCKETPAIR, ...) when first arg of sub-call is AF_UNIX
 *
 * This requires inspecting the arguments passed to socketcall, which is more
 * complex BPF logic. For now, 32-bit x86 is not supported.
 *
 * Compilation:
 *   gcc -o seccomp-unix-block seccomp-unix-block.c -lseccomp
 *
 * Usage:
 *   ./seccomp-unix-block <output-file> <block|allowlist> [arch]
 *
 * If arch is given (x86_64 or aarch64), the filter is generated for that
 * architecture instead of the native one. Lets a single-arch builder emit
 * filters for both x64 and arm64.
 *
 * Dependencies:
 *   - libseccomp (libseccomp-dev package on Debian/Ubuntu)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

static int add_io_uring_rules(scmp_filter_ctx ctx) {
    int io_uring_calls[] = {
        SCMP_SYS(io_uring_setup),
        SCMP_SYS(io_uring_enter),
        SCMP_SYS(io_uring_register),
    };
    for (size_t i = 0; i < sizeof(io_uring_calls) / sizeof(io_uring_calls[0]); i++) {
        int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), io_uring_calls[i], 0);
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add io_uring rule: %s\n", strerror(-rc));
            return rc;
        }
    }
    return 0;
}

static int add_allowlist_rules(scmp_filter_ctx ctx) {
    /* Path policy needs userspace memory, so connect() is handled by the
     * apply-seccomp USER_NOTIF supervisor. The supervisor emulates the call
     * from a copied sockaddr and never returns CONTINUE. */
    int rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(connect), 0);
    if (rc < 0) {
        fprintf(stderr, "Error: Failed to add connect notify rule: %s\n", strerror(-rc));
        return rc;
    }

    /* Only AF_UNIX stream sockets are useful for a path-scoped connect
     * allowlist. Block every other valid Unix socket type at creation time.
     * SOCK_CLOEXEC and SOCK_NONBLOCK live outside the low type mask. */
    const int socket_type_mask = 0x0f;
    const int blocked_types[] = {
        SOCK_DGRAM,
        SOCK_RAW,
        SOCK_RDM,
        SOCK_SEQPACKET,
#ifdef SOCK_DCCP
        SOCK_DCCP,
#endif
#ifdef SOCK_PACKET
        SOCK_PACKET,
#endif
    };
    for (size_t i = 0; i < sizeof(blocked_types) / sizeof(blocked_types[0]); i++) {
        rc = seccomp_rule_add(
            ctx,
            SCMP_ACT_ERRNO(EPERM),
            SCMP_SYS(socket),
            2,
            SCMP_A0(SCMP_CMP_MASKED_EQ, 0xffffffff, AF_UNIX),
            SCMP_A1(SCMP_CMP_MASKED_EQ, socket_type_mask, blocked_types[i])
        );
        if (rc < 0) {
            fprintf(stderr, "Error: Failed to add Unix socket type rule: %s\n", strerror(-rc));
            return rc;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    scmp_filter_ctx ctx;
    int rc;

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <output-file> <block|allowlist> [x86_64|aarch64]\n", argv[0]);
        return 1;
    }

    const char *output_file = argv[1];
    const char *mode = argv[2];
    const char *arch_name = (argc == 4) ? argv[3] : NULL;
    if (strcmp(mode, "block") != 0 && strcmp(mode, "allowlist") != 0) {
        fprintf(stderr, "Error: Unsupported mode '%s'\n", mode);
        return 1;
    }

    /* Create seccomp context with default action ALLOW */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Error: Failed to initialize seccomp context\n");
        return 1;
    }

    if (arch_name != NULL) {
        uint32_t target;
        if (strcmp(arch_name, "x86_64") == 0) {
            target = SCMP_ARCH_X86_64;
        } else if (strcmp(arch_name, "aarch64") == 0) {
            target = SCMP_ARCH_AARCH64;
        } else {
            fprintf(stderr, "Error: Unsupported arch '%s'\n", arch_name);
            seccomp_release(ctx);
            return 1;
        }
        if (target != seccomp_arch_native()) {
            rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
            if (rc == 0) rc = seccomp_arch_add(ctx, target);
            if (rc < 0) {
                fprintf(stderr, "Error: Failed to set target arch: %s\n", strerror(-rc));
                seccomp_release(ctx);
                return 1;
            }
        }
    }

    if (strcmp(mode, "block") == 0) {
        /* Use a 32-bit mask because socket()'s domain argument is an int and
         * the kernel ignores the upper half of the syscall register. */
        rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                              SCMP_A0(SCMP_CMP_MASKED_EQ, 0xffffffff, AF_UNIX));
    } else {
        rc = add_allowlist_rules(ctx);
    }
    if (rc < 0) {
        seccomp_release(ctx);
        return 1;
    }

    /* Block io_uring entirely. IORING_OP_SOCKET (Linux 5.19+) creates sockets
     * in kernel context without going through the socket() syscall, bypassing
     * the rule above. seccomp cannot inspect io_uring SQEs (they live in a
     * shared-memory ring), so the only safe option is to deny ring creation
     * and use. Blocking all three syscalls also covers the case of an
     * inherited ring fd. */
    rc = add_io_uring_rules(ctx);
    if (rc < 0) {
        seccomp_release(ctx);
        return 1;
    }

    /* Export the filter to a file */
    int fd = open(output_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open output file: %s\n", strerror(errno));
        seccomp_release(ctx);
        return 1;
    }

    rc = seccomp_export_bpf(ctx, fd);
    if (rc < 0) {
        fprintf(stderr, "Error: Failed to export seccomp filter: %s\n", strerror(-rc));
        close(fd);
        seccomp_release(ctx);
        return 1;
    }

    /* Clean up */
    close(fd);
    seccomp_release(ctx);

    return 0;
}
