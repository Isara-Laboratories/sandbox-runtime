#!/usr/bin/env python3
"""Opt-in live scoped-policy tests. Uses only temporary repos/profiles, no credentials.

npm run build && python3 test/repository-protection-linux.integration.py
Optionally add --source-repo /path/to/repo to check out its full committed tree
from a temporary shared clone (never modifies the source repository).
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

CLI = Path(__file__).resolve().parents[1] / 'dist/cli.js'
parser = argparse.ArgumentParser()
parser.add_argument('--source-repo', type=Path)
parser.add_argument('--filesystem-settings', type=Path, help='SRT settings whose deny/read-exception rules to retain')
options = parser.parse_args()
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', SHELL='/bin/bash')

def run(args, cwd, check=True):
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, text=True, capture_output=True, timeout=90)
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result

with tempfile.TemporaryDirectory(prefix='srt-repository-live-') as directory, tempfile.TemporaryDirectory(prefix='srt-outside-') as outside:
    base = Path(directory).resolve()
    root = base / 'repo'
    empty = base / 'empty-template'
    empty.mkdir()
    git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'user.name=Sandbox Test', '-c', 'user.email=test@example.invalid']
    if options.source_repo:
        run([*git, 'clone', '--shared', '--no-checkout', f'--template={empty}', options.source_repo.resolve(), root], base)
    else:
        root.mkdir()
        run([*git, 'init', '-q', f'--template={empty}'], root)
    tracked = {
        'README.md': 'original\n',
        '.claude/settings.json': '{}\n',
        'component/.claude/hooks/setup.sh': '# harmless fixture\n',
        'component/.claude/settings.json': '{}\n',
        'component/.mcp.json': '{"mcpServers":{}}\n',
        '.vscode/settings.json': '{}\n',
        '.pi/extensions/test.ts': '// harmless fixture\n',
    }
    for rel, text in tracked.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    if not options.source_repo:
        run([*git, 'add', '.'], root)
        run([*git, 'commit', '-qm', 'fixture'], root)
    (root / '.git/hooks').mkdir(exist_ok=True)
    (root / '.git/hooks/probe.txt').write_text('original hook fixture')
    (root / '.env').write_text('DUMMY=not-a-secret')
    readonly = Path(outside) / 'readonly.txt'
    readonly.write_text('outside')
    config = base / 'settings.json'
    filesystem = (
        json.loads(options.filesystem_settings.read_text())['filesystem']
        if options.filesystem_settings else {'allowRead': [], 'denyRead': ['**/.env'], 'denyWrite': []}
    )
    settings = {
        'network': {'allowedDomains': [], 'deniedDomains': [], 'allowAllDomains': True},
        'filesystem': {
            **filesystem,
            'linuxBackend': 'apparmor', 'allowGitConfig': True,
            # Deliberately put the ancestor last: it must not shadow the repo
            # barrier, as the old mount order did for repositories under /tmp.
            'allowWrite': [str(root), str(base)],
            'repositoryProtection': {
                'roots': [str(root)], 'worktreeRoots': [str(root / '.worktrees')],
                'gitDirectories': [str(root / '.git')],
            },
        },
    }
    config.write_text(json.dumps(settings))
    prefix = ['node', CLI, '--require-repository-protection', '--settings', config]
    policy = base / 'policy.apparmor'
    text = run([*prefix, '--print-apparmor-profile'], root).stdout
    assert '# srt-repository-protection-v1\n' in text
    assert not (root / '.worktrees').exists(), 'preview must not create directories'
    name = re.search(r'^profile (\S+)', text, re.M)[1]
    policy.write_text(text)
    run(['sudo', '-n', 'apparmor_parser', '-a', policy], root)
    loaded = [policy]
    try:
        probe = base / 'probe.py'
        probe.write_text(r'''
from pathlib import Path
import errno, json, os, shutil, subprocess, sys
root = Path.cwd(); base = root.parent; results = []
assert Path('/proc/self/attr/current').read_text().strip() == sys.argv[1] + ' (enforce)'
def check(label, allowed, fn, expected_errno=None):
    try:
        fn()
    except OSError as error:
        assert not allowed, (label, error)
        assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS, errno.EBUSY, errno.EXDEV), (label, error)
        if expected_errno is not None: assert error.errno == expected_errno, (label, error)
    else:
        assert allowed, label + ' unexpectedly allowed'
    results.append(label)
def write(p): return lambda: Path(p).write_text('updated')
check('main source writable', True, write('README.md'))
for rel in ['.claude/settings.json', 'component/.claude/hooks/setup.sh', 'component/.mcp.json', '.git/config', '.git/hooks/probe.txt', '.git/commondir', '.git/gitdir']:
    check('main config denied: ' + rel, False, write(rel))
check('future main config denied', False, lambda: (root/'new-component/.claude').mkdir(parents=True))
check('original secret denied', False, lambda: (root/'.env').read_text())
check('outside write roots denied', False, write(sys.argv[2]))
check('main .claude rename denied', False, lambda: os.rename('.claude','renamed-claude'))
check('main metadata rename denied', False, lambda: os.rename('.git','renamed-git'))
check('main repo rename denied', False, lambda: os.rename(root,base/'moved-repo'))
check('reserved worktree mount rename denied', False, lambda: os.rename('.worktrees','moved-worktrees'))
for label, destination in [('external',base/'scratch'), ('nested',root/'.worktrees/new')]:
    result = subprocess.run(['git','worktree','add','--detach',str(destination),'HEAD'], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (destination/'.git').is_file()
    results.append(label + ' full worktree checkout')
    for rel in ['.claude/settings.json','component/.claude/hooks/setup.sh','component/.mcp.json','.pi/extensions/test.ts']:
        path = destination/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        check(label + ' editable config: ' + rel, True, write(path))
    (destination/'replacement.json').write_text('{}')
    check(label + ' atomic config replacement', True, lambda: os.replace(destination/'replacement.json',destination/'.claude/settings.json'))
    check(label + ' copy config into main denied', False, lambda: shutil.copyfile(destination/'.claude/settings.json', root/'.claude/settings.json'))
    (destination/'main-config-alias').symlink_to(root/'.claude/settings.json')
    check(label + ' symlink alias cannot edit main', False, write(destination/'main-config-alias'))
    check(label + ' hardlink alias cannot edit main', False, lambda: os.link(root/'.claude/settings.json', destination/'hardlink'))
    (destination/'payload/.claude').mkdir(parents=True)
    (destination/'payload/.claude/settings.json').write_text('{}')
    check(label + ' move prepared config into main denied', False, lambda: os.rename(destination/'payload',root/('import-'+label)), errno.EXDEV)
    check(label + ' move original config out denied', False, lambda: os.rename(root/'component',destination/'original-component'), errno.EXDEV)
    check(label + ' shared hooks remain protected', False, write(root/'.git/hooks/probe.txt'))
    check(label + ' future secrets remain denied', False, write(destination/'.env'))
print(json.dumps({'passed':len(results),'checks':results}))
''')
        result = run([*prefix, '--', '/usr/bin/python3', probe, name, readonly], root)
        print(result.stdout.strip())
        assert (root / '.claude/settings.json').read_text() == tracked['.claude/settings.json']
        assert (root / '.git/hooks/probe.txt').read_text() == 'original hook fixture'
        # A new launch in an existing linked checkout protects that checkout too,
        # even though it lies in the main root's otherwise-untrusted worktree area.
        linked = root / '.worktrees/new'
        git_dir = Path(run(['git', 'rev-parse', '--absolute-git-dir'], linked).stdout.strip())
        scope = settings['filesystem']['repositoryProtection']
        scope['roots'].append(str(linked))
        scope['worktreeRoots'].append(str(linked / '.worktrees'))
        scope['gitDirectories'].append(str(git_dir))
        config.write_text(json.dumps(settings))
        linked_policy = base / 'linked.apparmor'
        linked_policy.write_text(run([*prefix, '--print-apparmor-profile'], linked).stdout)
        run(['sudo', '-n', 'apparmor_parser', '-a', linked_policy], linked)
        loaded.append(linked_policy)
        code = r'''
from pathlib import Path
import subprocess, sys
root, metadata, main = map(Path, sys.argv[1:])
for p in [root/'.git', root/'.claude/settings.json', metadata/'commondir', metadata/'gitdir', metadata/'config.worktree', main/'.git/commondir', main/'.claude/settings.json']:
    try: p.write_text('redirect')
    except PermissionError: pass
    else: raise AssertionError('linked-launch configuration writable: ' + str(p))
child = root/'.worktrees/child'
result = subprocess.run(['git','worktree','add','--detach',str(child),'HEAD'], capture_output=True,text=True)
assert result.returncode == 0, result.stdout + result.stderr
(child/'.claude').mkdir(exist_ok=True)
(child/'.claude/settings.json').write_text('{}')
print('linked launch: 7 config/routing denies and nested child checkout/edit passed')
'''
        print(run([*prefix, '--', '/usr/bin/python3', '-c', code, linked, git_dir, root], linked).stdout.strip())
    finally:
        for installed in reversed(loaded):
            run(['sudo', '-n', 'apparmor_parser', '-R', installed], root)
