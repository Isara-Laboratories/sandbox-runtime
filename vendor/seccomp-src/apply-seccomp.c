/*
 * apply-seccomp.c - Apply seccomp BPF filter in an isolated PID namespace
 *
 * Usage: apply-seccomp [--allow-unix-socket /absolute/path ... --] <command> [args...]
 *
 * This program applies a baked-in seccomp BPF filter and isolates the target
 * command in a nested user+PID+mount namespace so it cannot see or ptrace any
 * process that lacks the filter. With an allowlist, connect() is trapped to
 * the outer stub, which safely emulates the call from supervisor-owned copies
 * of the tracee descriptor and sockaddr.
 *
 * Process layout inside the outer bwrap sandbox:
 *
 *   bwrap init (PID 1)          <- outer PID ns, no seccomp
 *   \_ bash / socat ...         <- outer PID ns, no seccomp
 *      \_ apply-seccomp [outer] <- outer PID ns, waits for inner init
 *         ================================================= PID ns boundary
 *         \_ apply-seccomp [inner init] <- inner PID 1, PR_SET_DUMPABLE=0
 *            \_ user command            <- inner PID 2, seccomp applied
 *
 * From the user command's point of view /proc contains only its own process
 * tree. The bwrap init, bash wrapper, and socat helpers are not addressable,
 * so they cannot be ptraced or patched via /proc/N/mem even on systems with
 * kernel.yama.ptrace_scope=0. The inner init (PID 1) sets PR_SET_DUMPABLE=0
 * so it cannot be ptraced either.
 *
 * Any failure to set up the nested namespaces aborts with a non-zero exit
 * status; we never fall back to running the command without isolation.
 *
 * Compile: gcc -static -O2 -o apply-seccomp apply-seccomp.c
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#include "unix-block-bpf.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW(SECCOMP_IOC_MAGIC, 2, __u64)
#endif

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

#define MAX_ALLOWED_UNIX_SOCKETS 64

struct unix_socket_allowlist {
    const char *paths[MAX_ALLOWED_UNIX_SOCKETS];
    size_t count;
};

static int parse_command(
    int argc,
    char *argv[],
    struct unix_socket_allowlist *allowlist,
    char ***command_argv
) {
    int i = 1;
    memset(allowlist, 0, sizeof(*allowlist));

    while (i < argc && strcmp(argv[i], "--allow-unix-socket") == 0) {
        if (i + 1 >= argc) {
            fprintf(stderr, "apply-seccomp: --allow-unix-socket requires a path\n");
            return -1;
        }
        const char *path = argv[i + 1];
        size_t len = strnlen(path, sizeof(((struct sockaddr_un *)0)->sun_path));
        if (path[0] != '/' || len == 0 || len >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
            fprintf(stderr, "apply-seccomp: Unix socket allowlist paths must be absolute and shorter than sun_path\n");
            return -1;
        }
        if (allowlist->count >= MAX_ALLOWED_UNIX_SOCKETS) {
            fprintf(stderr, "apply-seccomp: too many Unix socket allowlist paths\n");
            return -1;
        }
        allowlist->paths[allowlist->count++] = path;
        i += 2;
    }

    if (allowlist->count > 0) {
        if (i >= argc || strcmp(argv[i], "--") != 0) {
            fprintf(stderr, "apply-seccomp: expected -- before the command\n");
            return -1;
        }
        i++;
    } else if (i < argc && strcmp(argv[i], "--") == 0) {
        i++;
    }

    if (i >= argc) {
        fprintf(stderr, "Usage: %s [--allow-unix-socket /absolute/path ... --] <command> [args...]\n", argv[0]);
        return -1;
    }
    *command_argv = &argv[i];
    return 0;
}

static int send_fd(int sock, int fd) {
    char marker = 'F';
    union {
        struct cmsghdr align;
        char control[CMSG_SPACE(sizeof(int))];
    } message_control;
    memset(&message_control, 0, sizeof(message_control));

    struct iovec iov = { .iov_base = &marker, .iov_len = 1 };
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = message_control.control,
        .msg_controllen = sizeof(message_control.control),
    };
    struct cmsghdr *control = CMSG_FIRSTHDR(&message);
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    control->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(control), &fd, sizeof(int));
    return sendmsg(sock, &message, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock) {
    char marker;
    union {
        struct cmsghdr align;
        char control[CMSG_SPACE(sizeof(int))];
    } message_control;
    memset(&message_control, 0, sizeof(message_control));

    struct iovec iov = { .iov_base = &marker, .iov_len = 1 };
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = message_control.control,
        .msg_controllen = sizeof(message_control.control),
    };
    if (recvmsg(sock, &message, 0) <= 0) {
        return -1;
    }
    for (
        struct cmsghdr *control = CMSG_FIRSTHDR(&message);
        control != NULL;
        control = CMSG_NXTHDR(&message, control)
    ) {
        if (
            control->cmsg_level == SOL_SOCKET &&
            control->cmsg_type == SCM_RIGHTS &&
            control->cmsg_len >= CMSG_LEN(sizeof(int))
        ) {
            int fd;
            memcpy(&fd, CMSG_DATA(control), sizeof(int));
            return fd;
        }
    }
    return -1;
}

static int unix_path_is_allowed(
    const struct sockaddr_un *address,
    socklen_t address_length,
    const struct unix_socket_allowlist *allowlist
) {
    const size_t path_offset = offsetof(struct sockaddr_un, sun_path);
    if (address_length <= path_offset + 1 || address->sun_family != AF_UNIX) {
        return 0;
    }

    size_t path_capacity = (size_t)address_length - path_offset;
    if (path_capacity > sizeof(address->sun_path)) {
        path_capacity = sizeof(address->sun_path);
    }
    if (address->sun_path[0] != '/') {
        return 0;
    }
    const char *terminator = memchr(address->sun_path, '\0', path_capacity);
    if (terminator == NULL) {
        return 0;
    }
    size_t path_length = (size_t)(terminator - address->sun_path);
    for (size_t i = 0; i < allowlist->count; i++) {
        const char *allowed = allowlist->paths[i];
        if (strlen(allowed) == path_length && memcmp(allowed, address->sun_path, path_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static void deny_connect(struct seccomp_notif_resp *response, uint64_t id, int error) {
    memset(response, 0, sizeof(*response));
    response->id = id;
    response->error = -error;
}

static pid_t read_thread_group_id(int host_proc_fd, pid_t thread_id) {
    if (host_proc_fd < 0) {
        return -1;
    }
    char relative_path[64];
    int path_length = snprintf(
        relative_path,
        sizeof(relative_path),
        "%d/status",
        (int)thread_id
    );
    if (path_length <= 0 || (size_t)path_length >= sizeof(relative_path)) {
        return -1;
    }

    int status_fd = openat(host_proc_fd, relative_path, O_RDONLY | O_CLOEXEC);
    if (status_fd < 0) {
        return -1;
    }
    char status[4096];
    ssize_t bytes_read = read(status_fd, status, sizeof(status) - 1);
    close(status_fd);
    if (bytes_read <= 0) {
        return -1;
    }
    status[bytes_read] = '\0';

    const char *field = strstr(status, "Tgid:\t");
    if (field == NULL) {
        return -1;
    }
    field += strlen("Tgid:\t");
    char *end = NULL;
    long parsed = strtol(field, &end, 10);
    if (end == field || parsed <= 0 || parsed > INT32_MAX) {
        return -1;
    }
    return (pid_t)parsed;
}

static void emulate_connect(
    int notify_fd,
    const struct seccomp_notif *request,
    struct seccomp_notif_resp *response,
    const struct unix_socket_allowlist *allowlist,
    int host_proc_fd
) {
    deny_connect(response, request->id, EPERM);

    uint64_t raw_length = request->data.args[2];
    if (raw_length < sizeof(sa_family_t) || raw_length > sizeof(struct sockaddr_storage)) {
        return;
    }
    socklen_t address_length = (socklen_t)raw_length;
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    struct iovec local = { .iov_base = &address, .iov_len = address_length };
    struct iovec remote = {
        .iov_base = (void *)(uintptr_t)request->data.args[1],
        .iov_len = address_length,
    };
    ssize_t copied = process_vm_readv(request->pid, &local, 1, &remote, 1, 0);
    if (copied != (ssize_t)address_length) {
        return;
    }

    pid_t process_id = read_thread_group_id(host_proc_fd, request->pid);
    if (process_id < 0) {
        process_id = request->pid;
    }
    int pidfd = (int)syscall(__NR_pidfd_open, process_id, 0);
    if (pidfd < 0) {
        return;
    }
    int copied_fd = (int)syscall(
        __NR_pidfd_getfd,
        pidfd,
        (int)(uint32_t)request->data.args[0],
        0
    );
    close(pidfd);
    if (copied_fd < 0) {
        return;
    }

    int domain = 0;
    socklen_t option_length = sizeof(domain);
    if (getsockopt(copied_fd, SOL_SOCKET, SO_DOMAIN, &domain, &option_length) < 0) {
        close(copied_fd);
        return;
    }

    const struct sockaddr *socket_address = (const struct sockaddr *)&address;
    if (domain == AF_UNIX) {
        int type = 0;
        option_length = sizeof(type);
        if (
            getsockopt(copied_fd, SOL_SOCKET, SO_TYPE, &type, &option_length) < 0 ||
            type != SOCK_STREAM ||
            !unix_path_is_allowed((const struct sockaddr_un *)&address, address_length, allowlist)
        ) {
            close(copied_fd);
            return;
        }
    } else if (socket_address->sa_family == AF_UNIX) {
        close(copied_fd);
        return;
    }

    /* The tracee memory has already been copied and the exact open file
     * description has already been duplicated. Validate the notification
     * immediately before the side effect, then connect using only those
     * supervisor-owned values. */
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) < 0) {
        close(copied_fd);
        return;
    }

    int result = connect(copied_fd, socket_address, address_length);
    int saved_errno = errno;
    close(copied_fd);

    memset(response, 0, sizeof(*response));
    response->id = request->id;
    if (result < 0) {
        response->error = -saved_errno;
    } else {
        response->val = result;
    }
}

static void supervise_connects(
    pid_t child,
    int notify_fd,
    const struct unix_socket_allowlist *allowlist,
    int host_proc_fd
) {
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        sizes.seccomp_notif = sizeof(struct seccomp_notif);
        sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    struct seccomp_notif *request = calloc(1, sizes.seccomp_notif);
    struct seccomp_notif_resp *response = calloc(1, sizes.seccomp_notif_resp);
    if (request == NULL || response == NULL) {
        free(request);
        free(response);
        return;
    }

    int child_pidfd = (int)syscall(__NR_pidfd_open, child, 0);
    struct pollfd poll_fds[2] = {
        { .fd = notify_fd, .events = POLLIN },
        { .fd = child_pidfd, .events = POLLIN },
    };
    nfds_t count = child_pidfd >= 0 ? 2 : 1;
    int timeout = child_pidfd >= 0 ? -1 : 200;

    for (;;) {
        int poll_result = poll(poll_fds, count, timeout);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (poll_fds[0].revents & POLLIN) {
            memset(request, 0, sizes.seccomp_notif);
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, request) == 0) {
                if (request->data.nr == __NR_connect) {
                    emulate_connect(
                        notify_fd,
                        request,
                        response,
                        allowlist,
                        host_proc_fd
                    );
                } else {
                    deny_connect(response, request->id, EPERM);
                }
                (void)ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, response);
            } else if (errno != EINTR && errno != ENOENT) {
                break;
            }
        }
        if (poll_fds[0].revents & (POLLHUP | POLLERR)) {
            break;
        }
        if (child_pidfd >= 0) {
            if (poll_fds[1].revents != 0) {
                break;
            }
        } else {
            siginfo_t child_info = {0};
            if (
                waitid(P_PID, (id_t)child, &child_info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
                child_info.si_pid == child
            ) {
                break;
            }
        }
    }

    if (child_pidfd >= 0) {
        close(child_pidfd);
    }
    free(request);
    free(response);
}

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static void install_allowlist_filter(const struct sock_fprog *program, int socketpair_fd) {
    int notify_fd = (int)syscall(
        SYS_seccomp,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        program
    );
    if (notify_fd < 0) {
        die("apply-seccomp: seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER)");
    }
    if (send_fd(socketpair_fd, notify_fd) < 0) {
        die("apply-seccomp: send notify fd");
    }
    close(socketpair_fd);
    close(notify_fd);
}

static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len < 0 || (size_t)len >= sizeof(buf)) {
        errno = EOVERFLOW;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t r = write(fd, buf, (size_t)len);
    int saved = errno;
    close(fd);
    if (r != len) {
        errno = (r < 0) ? saved : EIO;
        return -1;
    }
    return 0;
}

/* PID the current process forwards signals to. Used by both the outer stub
 * (forwards to inner init) and the inner init (forwards to the worker).
 * PID 1 ignores signals it has no handler for, so the inner init MUST install
 * these or SIGTERM from the outside is silently dropped. */
static volatile pid_t forward_target = -1;

static void forward_signal(int sig) {
    if (forward_target > 0) {
        kill(forward_target, sig);
    }
}

static void install_forwarders(pid_t target) {
    forward_target = target;
    struct sigaction sa = { .sa_handler = forward_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

/*
 * Wait for `main_child`, reaping any other children that exit first.
 * Returns as soon as `main_child` terminates — the caller then _exit()s,
 * which as PID 1 tears down the namespace and SIGKILLs any stragglers.
 * Returns an exit(3)-style status: exit code, or 128+signal.
 */
static int reap_until(pid_t main_child) {
    int status = 0;
    for (;;) {
        pid_t r = waitpid(-1, &status, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;  /* ECHILD without seeing main_child — shouldn't happen. */
        }
        if (r == main_child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 1;
        }
        /* Reaped an orphan that died before main_child; keep waiting. */
    }
}

int main(int argc, char *argv[]) {
    struct unix_socket_allowlist allowlist;
    char **command_argv = NULL;
    if (parse_command(argc, argv, &allowlist, &command_argv) < 0) {
        return 1;
    }

    _Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
                   "BPF filter size must be a multiple of sock_filter");
    _Static_assert(sizeof(unix_allowlist_bpf) % sizeof(struct sock_filter) == 0,
                   "allowlist BPF filter size must be a multiple of sock_filter");
    struct sock_fprog block_program = {
        .len = (unsigned short)(sizeof(unix_block_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)unix_block_bpf,
    };
    struct sock_fprog allowlist_program = {
        .len = (unsigned short)(sizeof(unix_allowlist_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)unix_allowlist_bpf,
    };

    int notification_pair[2] = { -1, -1 };
    if (
        allowlist.count > 0 &&
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, notification_pair) < 0
    ) {
        die("apply-seccomp: socketpair");
    }

    /* The child mounts a fresh /proc for the nested PID namespace in the
     * shared mount namespace. Pin the current procfs first so the supervisor
     * can map a notifying thread ID to its thread-group leader for
     * pidfd_getfd(). */
    int host_proc_fd = allowlist.count > 0
        ? open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC)
        : -1;
    if (allowlist.count > 0 && host_proc_fd < 0) {
        die("apply-seccomp: open(/proc)");
    }

    /* ---- New PID + mount namespaces. Children (not us) enter the PID ns. ----
     *
     * Two paths to get CAP_SYS_ADMIN for the unshare:
     *   (a) The caller (bwrap) kept CAP_SYS_ADMIN in this user namespace via
     *       --cap-add. Just unshare directly.
     *   (b) We don't have the cap. Create a nested user namespace to get it,
     *       map uid/gid, then unshare. This also works when apply-seccomp is
     *       run standalone outside bwrap.
     *
     * Path (a) is tried first. If the caller didn't give us the cap, the
     * kernel returns EPERM and we fall through to (b). Path (b) can itself
     * fail on hosts where unprivileged user namespaces are gated by an LSM
     * (Ubuntu 24.04's AppArmor restriction, for example) — the unshare
     * succeeds but the new namespace grants no capabilities, so the setgroups
     * write fails. In that case we abort: the caller must supply CAP_SYS_ADMIN.
     */
    if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
        if (errno != EPERM) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS)");
        }

        uid_t uid = geteuid();
        gid_t gid = getegid();

        if (unshare(CLONE_NEWUSER) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWUSER)");
        }
        if (write_file("/proc/self/setgroups", "deny") < 0) {
            die("apply-seccomp: write /proc/self/setgroups "
                "(nested userns is capability-restricted; "
                "caller must provide CAP_SYS_ADMIN)");
        }
        if (write_file("/proc/self/uid_map", "%u %u 1\n", uid, uid) < 0) {
            die("apply-seccomp: write /proc/self/uid_map");
        }
        if (write_file("/proc/self/gid_map", "%u %u 1\n", gid, gid) < 0) {
            die("apply-seccomp: write /proc/self/gid_map");
        }
        if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns");
        }
    }

    pid_t child = fork();
    if (child < 0) {
        die("apply-seccomp: fork");
    }

    if (child > 0) {
        /* Outer stub: still in bwrap's PID namespace and never filtered.
         * It owns path policy and emulates trapped connect() calls. */
        if (notification_pair[1] >= 0) {
            close(notification_pair[1]);
        }
        install_forwarders(child);

        if (notification_pair[0] >= 0) {
            int notify_fd = recv_fd(notification_pair[0]);
            close(notification_pair[0]);
            if (notify_fd >= 0) {
                supervise_connects(child, notify_fd, &allowlist, host_proc_fd);
                close(notify_fd);
            }
        }
        if (host_proc_fd >= 0) {
            close(host_proc_fd);
        }

        int status;
        for (;;) {
            pid_t r = waitpid(child, &status, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) die("apply-seccomp: waitpid");
            break;
        }
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }

    if (notification_pair[0] >= 0) {
        close(notification_pair[0]);
    }
    if (host_proc_fd >= 0) {
        close(host_proc_fd);
    }

    /* ================================================================
     * Inner init — PID 1 in the nested PID namespace.
     * ================================================================ */

    /* Block ptrace and /proc/1/mem writes against this process. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_DUMPABLE)");
    }

    /* Don't let our /proc mount propagate anywhere. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        die("apply-seccomp: mount(MS_PRIVATE)");
    }
    /* EPERM here means a masked /proc is underneath (unprivileged Docker)
     * and the kernel domination check refused the overmount. The nested
     * userns above is the isolation boundary; this remount only hides
     * outer PIDs from `ls /proc`. enableWeakerNestedSandbox targets
     * exactly this environment. */
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0
        && errno != EPERM) {
        die("apply-seccomp: mount(/proc)");
    }

    /* bwrap --cap-add places CAP_SYS_ADMIN in the ambient set so it survives
     * exec. Clear it now that the mount is done; combined with
     * PR_SET_NO_NEW_PRIVS, the worker's execve drops to zero capabilities. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_CAP_AMBIENT_CLEAR_ALL)");
    }

    /* Fork the real workload so PID 1 can stay as a non-dumpable reaper. */
    pid_t worker = fork();
    if (worker < 0) {
        die("apply-seccomp: fork(worker)");
    }

    if (worker > 0) {
        /* Inner init: reap everything, exit with the worker's status.
         * When PID 1 exits the kernel tears down the whole namespace.
         * PID 1 drops signals without handlers, so install forwarders. */
        if (notification_pair[1] >= 0) {
            close(notification_pair[1]);
        }
        install_forwarders(worker);
        _exit(reap_until(worker));
    }

    /* ---- Worker (inner PID 2): apply seccomp and exec. ---- */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (allowlist.count > 0) {
        install_allowlist_filter(&allowlist_program, notification_pair[1]);
    } else if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &block_program) < 0) {
        die("apply-seccomp: prctl(PR_SET_SECCOMP)");
    }

    execvp(command_argv[0], command_argv);
    die("apply-seccomp: execvp");
    return 1;
}
