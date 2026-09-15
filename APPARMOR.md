# Experimental Linux AppArmor filesystem backend

This opt-in backend splits filesystem enforcement so that **one loaded AppArmor
profile serves every repository**:

- **AppArmor** enforces every rule that does not depend on the launch directory:
  `denyRead`, `allowRead` exceptions, `denyWrite`, and the mandatory protections
  (`.git/hooks`, shell startup files, …). Recursive selectors such as `**/.env`
  apply system-wide. The profile name is a SHA-256 of these rules only.
- **Bubblewrap mounts** enforce `allowWrite`: a read-only root plus read-write
  binds of the literal writable roots, applied per launch without privilege.
  AppArmor forbids the sandbox from changing mounts or namespaces.

There is no `fd`, `find`, or `rg` traversal in either step. macOS and the default
Linux backend are unchanged. Bubblewrap still supplies fresh `/dev` and `/proc`,
PID and network namespaces; the proxy and apply-seccomp socket controls remain.
The trusted namespace setup runs before the workload enters AppArmor. The workload
profile grants no mount, capability, profile-transition, or outbound ptrace
permissions. A guard verifies the exact profile name and `(enforce)` mode **before**
starting the user's shell/startup files. Missing profiles, complain mode, unsupported
policy syntax, glob `allowWrite` entries, or unavailable required socket filtering
stop the launch; there is no unconfined fallback.

`filesystem.secretFiles` names host files to expose despite `denyRead`: each is
bind-mounted read-only at `/dev/srt/secrets/<index>-<basename>` inside bwrap's
fresh `/dev`, so the profile does not change per secret. The original path stays
denied. Launch fails if the compiled deny rules would cover the alias path.

## Build and try without installing

```
npm ci                 # or use an existing compatible node_modules for development
npm run build

# Run both preparation and launch from the intended workload directory.
node /path/to/this/worktree/dist/cli.js --settings /path/to/settings.json \
  --print-apparmor-profile > /tmp/my-agent.apparmor

# Review the generated profile. This is the only privileged step.
sudo apparmor_parser -a /tmp/my-agent.apparmor
node /path/to/this/worktree/dist/cli.js --settings /path/to/settings.json \
  --apparmor -- /bin/true

# After ALL processes using this profile have exited:
sudo apparmor_parser -R /tmp/my-agent.apparmor
```

Alternatively set `filesystem.linuxBackend` to `"apparmor"` in the settings.
`--apparmor` explicitly errors on non-Linux platforms; the `linuxBackend` config
field is ignored on macOS. `--print-apparmor-profile` does not start proxies or a
workload and does not load kernel policy.

Profile names (`srt-fs-v2-<hash>`) contain a SHA-256 of the deny/exception rules,
not of write roots, secret files, cwd, or a session ID. One load serves every
repository and worktree. Only changed deny/exception rules, resolved symlink
targets of literal policy paths, or compiler output require a new profile.
Network-only changes never do. Manual loads last until reboot or removal; boot-time loading is not
configured automatically. Reload a saved matching policy after reboot.

Do not reload or remove profiles while their workloads are active. Nothing
automatically installs a privileged helper, writes sudoers, replaces an installed
executable, or gives sandboxed agents permission to load policy. A managed
deployment can provision approved profiles in advance; a general privileged loader
is out of scope.

The compiler resolves only explicitly supplied literal paths/static prefixes. It
does not enumerate their contents. Cold compilation/loading is a separate setup
cost; warm launch still generates the deterministic policy/name, but skips
`apparmor_parser` and filesystem traversal.

## Which processes are confined?

Generated profiles have names such as `srt-fs-v2-<hash>` and **no executable
attachment**. Loading them does not automatically attach them to `pi`, `node`,
Python, shells, or existing processes. The launcher explicitly selects the named
profile with `/usr/bin/aa-exec -p NAME -- ...` after namespace setup. Its guard
checks `/proc/self/attr/current` before user startup files run. Descendants inherit
the profile through `ix` rules, with no permission to transition out of it.

Other independent processes keep their existing confinement. This is not an
Isara-only identity check: any otherwise permitted process can explicitly select
the profile. See the [`aa-exec` manual](https://manpages.ubuntu.com/manpages/noble/en/man1/aa-exec.1.html)
and [`ix` execution semantics](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html).

Because write roots and secret files live in per-launch mounts, a named sandbox
template such as Isara's `git` compiles to one profile for every repository,
worktree, and `--secrets` run. Never replace a loaded profile with different rules
while workloads use it; different rules get a different hash instead.

## Policy semantics and current limitations

This is a bounded experimental compiler, not a drop-in implementation of every
possible SRT glob. It supports the built-in Isara git profile and its normal
`.env` template and literal `--secrets` exceptions.

- AppArmor denies override allows. The compiler subtracts read exceptions from
  the denied patterns **before** emitting rules. It does not pretend that putting
  an allow after a deny works.
- Literal paths and `*`, `**`, `**/`, and `?` path patterns are supported. Config
  strings containing bracket expressions, braces, backslashes, quotes, control
  characters, `@`, or non-ASCII characters are rejected. Files with non-ASCII names
  under an otherwise allowed directory are not thereby forbidden.
- Glob read exceptions must be recursive basename selectors with at most one
  `*` in the basename. Matching read-deny selectors use the same static root.
  Unsupported combinations fail before launching. Complexity is bounded.
- Literal read exceptions support files and subtrees. An existing regular-file
  exception grants that file, not hypothetical future descendants under its name.
- **Conservative directory behavior:** a template-name glob does not reopen a
  file inside an otherwise denied directory. Use an explicit literal `allowRead`
  for that case. For example `.ssh/.env.example` does not bypass a `.ssh` deny.
  Overlapping read-exception scopes outside the shared basename root remain denied.
- **Denied-read objects are also immutable.** Unlike Seatbelt, AppArmor's `w`
  permission does not separate ordinary writes from renaming/unlinking. Denying
  mutation prevents renaming a secret to a readable name. A literal read carveout
  does not override any independent write deny.
- Protected literal ancestors are immutable to prevent moving policy roots.
  Mandatory configuration paths are protected at every depth, including future
  files, rather than only existing paths within the old depth-limited cwd scan.
- `**/`-prefixed selectors are system-wide, stricter than the legacy
  project-local expansion. Other relative patterns still resolve against cwd
  and therefore produce per-directory profiles; prefer absolute or `**/` forms.
- `allowWrite` entries must be literal paths (they become bind mounts). Writes
  outside them fail with `EROFS`; denies inside them are AppArmor `EACCES`.
- `.mcp.json` is not a mandatory deny. Existing and newly checked-out MCP plugin
  configuration can be edited inside writable roots, unless an explicit deny
  covers it. Review changes before loading that configuration in a trusted client.
  Git hook, shell startup file, and secret-file protections are unchanged.
- **Creating new protected directories is denied too**, notably `.git`, `.vscode`,
  and `.idea`. Existing repositories can update normal git files (including config
  with `allowGitConfig`), but run `git init` or `git clone` on the host before
  starting the sandbox. This prevents renaming `.git` to an unprotected name,
  changing its hooks, and moving it back. Linked worktrees can be created inside
  writable roots: their `.git` marker is a file, not a directory. Their checkout
  contents must still obey all other deny rules.
- `/proc` and `/sys` are always non-writable, even with `allowWrite: ["/"]`.
  Mounts, namespace-map writes, and profile changes remain prohibited.
- This remains path-based access control, not encryption or inode labeling.
  Pre-existing alternate hardlinks and already-open secret descriptors need
  separate consideration; do not pass secret descriptors into the workload.
- Existing confinement on the caller may prevent entering the profile after
  `no_new_privs`. That fails closed. The tested host enters from `unconfined`.

Do not make this the default backend before reviewing these compatibility changes
and performing a broader security review. In particular, generated deny rules
must not be removed merely to make an application work.

## Tests

```
npm run build
node --test test/apparmor-patterns.node.test.mjs
python3 test/apparmor-linux.integration.py
python3 test/apparmor-benchmark.py --cwd /path/to/large/repo \
  --settings /path/to/real-profile.json --repeat 3 --legacy-timeout 60
```

The Python tests use dummy files and named temporary profiles, require
`sudo -n apparmor_parser`, and unload only profiles they loaded. The integration
test checks allowed/denied file access, templates, explicit read exceptions,
mutations/links, inheritance, future and atomically replaced secrets, missing and
complain-mode profiles, Unix socket allowlisting, and HTTP proxy/network isolation.

The benchmark runs `/bin/true` through identical policies with each backend,
records separate policy generation/load costs, bounds expensive legacy runs, and
uses `strace` to verify that AppArmor launches execute no filesystem scanner.
It measures sandbox startup, not key minting or Pi's interactive readiness.
