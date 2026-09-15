#!/usr/bin/env python3
"""Opt-in real-kernel tests. Loads only generated, unique test profiles; removes them.
Run after npm run build: python3 test/apparmor-linux.integration.py
Requires Linux/AppArmor, sudo -n apparmor_parser, bubblewrap and srt dependencies.
No real secrets, model calls, or installed CLI changes.
"""
import json
import http.server
import socket
import threading
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'dist/cli.js'
PARSER = '/usr/sbin/apparmor_parser'
fixture = Path(tempfile.mkdtemp(prefix='srt-apparmor-test-'))
code = fixture / 'code'
code.mkdir()
for directory in ['config', 'private', '.git/hooks', 'nested', 'outside', 'restricted']:
    (code / directory).mkdir(parents=True, exist_ok=True)
files = {
    'normal.txt': 'normal', 'config/.env': 'secret', 'config/.env.local': 'local',
    'config/.env.production': 'production', 'config/.env.surprise': 'surprise',
    'config/.env.example': 'example', 'config/.env.example.local': 'example local',
    'config/.env.local.example': 'local example', 'config/givetrack.env.example': 'example',
    'config/.envrc': 'envrc', 'private/secret.txt': 'private', 'private/public.txt': 'public',
    '.git/config': 'git', '.git/hooks/pre-commit': 'hook', '.bashrc': 'bashrc',
    'security_profile.json': '{}', 'nested/.env': 'authorized', 'nested/.env.local': 'authorized local',
    '.mcp.json': '{}', 'nested/.mcp.json': '{}', 'restricted/.mcp.json': '{}',
}
for name, value in files.items():
    (code / name).write_text(value)
(code / 'alias').symlink_to(code / 'config/.env')
(code / 'private-alias').symlink_to(code / 'private', target_is_directory=True)
(fixture / 'read-only.txt').write_text('read-only')
(fixture / '.mcp.json').write_text('{}')
settings = {
    'ripgrep': {'command': '/deliberately-absent-ripgrep'},
    'network': {'allowedDomains': [], 'deniedDomains': [], 'allowAllDomains': True},
    'filesystem': {
        'linuxBackend': 'apparmor', 'allowGitConfig': True,
        'denyRead': [str(code / 'private'), '**/.env', '**/.env.*'],
        'allowRead': ['**/.env.example', '**/.env.example.*', '**/.env.*.example', '**/*.env.example', '**/.envrc', str(code / 'private/public.txt'), str(code / 'nested/.env'), str(code / 'nested/.env.local')],
        'allowWrite': [str(code)],
        'denyWrite': ['**/.env', '**/.env.local', '**/.env.production', '**/security_profile.json', str(code / 'restricted/.mcp.json')],
    },
}
config = fixture / 'settings.json'
config.write_text(json.dumps(settings))
base = ['node', str(CLI), '--settings', str(config)]
env = {**os.environ, 'SRT_DEBUG': '1', 'SHELL': '/bin/bash'}
loaded = []
results = []

def run(args, cwd=code, **kwargs):
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=30, **kwargs)

def load(profile):
    result = run(['sudo', '-n', PARSER, '-a', str(profile)])
    assert result.returncode == 0, result.stderr
    loaded.append(profile)

def unload(profile):
    result = run(['sudo', '-n', PARSER, '-R', str(profile)])
    assert result.returncode == 0, result.stderr
    loaded.remove(profile)

try:
    generated = run([*base, '--print-apparmor-profile'])
    assert generated.returncode == 0, generated.stderr
    profile = fixture / 'policy.apparmor'
    profile.write_text(generated.stdout)
    (fixture / 'generation.stderr').write_text(generated.stderr)

    missing = run([*base, '--', '/bin/sh', '-c', 'touch should-not-run'])
    assert missing.returncode != 0 and not (code / 'should-not-run').exists()
    results.append({'test': 'missing profile fails closed', 'passed': True})
    load(profile)

    probe = fixture / 'probe.py'
    probe.write_text(r'''
import errno,json,os,pathlib,socket,subprocess,sys
root=pathlib.Path.cwd(); results=[]
def check(name,allowed,fn):
    try: fn(); success=True
    except OSError as e:
        if e.errno not in (errno.EACCES,errno.EPERM,errno.EROFS): raise
        success=False
    assert success == allowed, (name, 'allowed' if success else 'denied')
    results.append({'test':name,'passed':True})
def read(p): return lambda: pathlib.Path(p).read_text()
def write(p): return lambda: pathlib.Path(p).write_text('updated')
for p in ['normal.txt','config/.env.example','config/.env.example.local','config/.env.local.example','config/givetrack.env.example','config/.envrc','private/public.txt','nested/.env','nested/.env.local','.git/config','.bashrc','security_profile.json','.mcp.json','nested/.mcp.json']:
    check('read '+p,True,read(p))
for p in ['normal.txt','config/.env.example','config/.env.example.local','config/.env.local.example','config/givetrack.env.example','config/.envrc','.git/config','new.txt','.mcp.json','nested/.mcp.json']:
    check('write '+p,True,write(p))
for p in ['config/.env','config/.env.local','config/.env.production','config/.env.surprise','private/secret.txt','alias','private-alias/secret.txt']:
    check('deny read '+p,False,read(p))
for p in ['config/.env','config/.env.local','config/.env.production','private/secret.txt','nested/.env','nested/.env.local','.git/hooks/pre-commit','.bashrc','security_profile.json','restricted/.mcp.json']:
    check('deny write '+p,False,write(p))
(root/'plugins/example').mkdir(parents=True)
check('create nested MCP config after launch',True,write('plugins/example/.mcp.json'))
(root/'replacement.json').write_text('{}')
check('atomically replace MCP config',True,lambda:os.replace('replacement.json','.mcp.json'))
check('MCP config outside write root',False,write(root.parent/'.mcp.json'))
check('outside write root',False,write(root.parent/'read-only.txt'))
check('outside read remains permitted',True,read(root.parent/'read-only.txt'))
check('mkdir ordinary directory',True,lambda:(root/'new-directory').mkdir())
check('rename ordinary file',True,lambda:os.rename('new.txt','renamed.txt'))
check('rename secret file',False,lambda:os.rename('config/.env','config/plain'))
check('rename literal secret ancestor',False,lambda:os.rename('private','moved-private'))
check('rename directory within glob scope',True,lambda:os.rename('config','moved-config'))
check('secret remains denied after parent rename',False,read('moved-config/.env'))
check('restore directory within glob scope',True,lambda:os.rename('moved-config','config'))
check('rename protected git ancestor',False,lambda:os.rename('.git','moved-git'))
check('hardlink secret to readable alias',False,lambda:os.link('config/.env','plain-hardlink'))
check('create mandatory dangerous file',False,write('nested/.bashrc'))
check('mandatory names remain case-insensitive',False,write('nested/.BASHRC'))
check('create protected git directory',False,lambda:(root/'nested/.git').mkdir())
check('no policy transition',False,lambda:open('/proc/self/attr/exec','w').write('exec unconfined'))
check('Unix sockets remain seccomp-blocked',False,lambda:socket.socket(socket.AF_UNIX,socket.SOCK_STREAM))
check('INET socket creation works',True,lambda:socket.socket(socket.AF_INET,socket.SOCK_STREAM).close())
mount=subprocess.run(['unshare','-Ur','--mount','/bin/true'],capture_output=True)
assert mount.returncode != 0, 'mount/usernamespace escape was allowed'
results.append({'test':'mount/usernamespace escape denied','passed':True})
child=subprocess.run(['/usr/bin/python3','-c',"open('config/.env').read()"],capture_output=True)
assert child.returncode != 0 and b'PermissionError' in child.stderr
results.append({'test':'descendants inherit enforcement','passed':True})
print('READY',flush=True);sys.stdin.readline()
check('host-created secret after launch',False,read('late/deep/.env'))
check('host-replaced secret after launch',False,read('config/.env'))
check('host-created ordinary file after launch',True,read('late/deep/ordinary'))
print(json.dumps(results),flush=True)
''')
    p = subprocess.Popen([*base, '--', '/usr/bin/python3', str(probe)], cwd=code, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # stderr can exceed a pipe buffer with debugging; this backend must stay small.
    ready = p.stdout.readline().strip()
    if ready != 'READY':
        stdout, stderr = p.communicate(timeout=10)
        raise AssertionError(f'probe did not reach READY: {ready}\n{stdout}\n{stderr}')
    (code / 'late/deep').mkdir(parents=True)
    (code / 'late/deep/.env').write_text('new dummy secret')
    (code / 'late/deep/ordinary').write_text('new ordinary file')
    replacement = code / 'replacement'
    replacement.write_text('replacement dummy secret')
    replacement.replace(code / 'config/.env')
    stdout, stderr = p.communicate('\n', timeout=20)
    (fixture / 'probe.stderr').write_text(stderr)
    assert p.returncode == 0, stdout + stderr
    assert 'Expanded ' not in stderr and 'ripgrep scan' not in stderr
    results.extend(json.loads(stdout.strip()))
    results.append({'test': 'runtime logs contain no glob expansion', 'passed': True})
    settings['network']['allowAllUnixSockets'] = True
    config.write_text(json.dumps(settings))
    no_other_restrictions = run([*base, '--', '/usr/bin/python3', '-c',
        'from pathlib import Path\ntry: Path("config/.env").read_text()\nexcept PermissionError: pass\nelse: raise AssertionError("filesystem-only sandbox bypass")'])
    assert no_other_restrictions.returncode == 0, no_other_restrictions.stderr
    results.append({'test': 'filesystem enforcement remains when network and socket restrictions are disabled', 'passed': True})
    settings['network'].pop('allowAllUnixSockets')

    # Interactive launches inherit a host terminal that has no path in bwrap's
    # fresh /dev. Node aborts unless such descriptors remain usable.
    import pty
    master, slave = pty.openpty()
    tty_probe = subprocess.run([*base, '--', '/usr/bin/python3', '-c',
        'import os,sys; os.fstat(0); os.fstat(1); print(os.isatty(0))'],
        cwd=code, env=env, stdin=slave, stdout=slave, stderr=subprocess.PIPE, text=True, timeout=30)
    os.close(slave)
    output = b''
    try:
        while True:
            chunk = os.read(master, 4096)
            if not chunk: break
            output += chunk
    except OSError:
        pass
    os.close(master)
    assert tty_probe.returncode == 0 and b'True' in output, (output, tty_probe.stderr)
    results.append({'test': 'inherited host terminal descriptors remain usable (attach_disconnected)', 'passed': True})

    # AppArmor must not break apply-seccomp's unconfined Unix-socket supervisor.
    allowed_socket = fixture / 'allowed.sock'
    denied_socket = fixture / 'denied.sock'
    listeners = []
    for socket_path in [allowed_socket, denied_socket]:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path)); listener.listen(); listeners.append(listener)
    def serve_socket():
        conn, _ = listeners[0].accept()
        with conn: conn.sendall(b'dummy socket response')
    thread = threading.Thread(target=serve_socket, daemon=True); thread.start()
    settings['network']['allowUnixSockets'] = [str(allowed_socket)]
    config.write_text(json.dumps(settings))
    socket_probe = run([*base, '--', '/usr/bin/python3', '-c',
        'import socket,sys; a=socket.socket(socket.AF_UNIX); a.connect(sys.argv[1]); '
        'assert a.recv(100)==b"dummy socket response"; b=socket.socket(socket.AF_UNIX); '
        '\ntry: b.connect(sys.argv[2])\nexcept PermissionError: pass\nelse: raise AssertionError("socket allowlist bypass")',
        str(allowed_socket), str(denied_socket)])
    for listener in listeners: listener.close()
    assert socket_probe.returncode == 0, socket_probe.stderr
    results.append({'test': 'Unix socket allowlist permits only named socket', 'passed': True})

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b'dummy HTTP response')
        def log_message(self, *_args): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    settings['network'] = {'allowedDomains': ['localhost'], 'deniedDomains': []}
    config.write_text(json.dumps(settings))
    network_probe = run([*base, '--', '/usr/bin/python3', '-c',
        'import http.client,socket,sys; port=int(sys.argv[1]); '
        'p=http.client.HTTPConnection("127.0.0.1",3128,timeout=5); '
        'p.request("GET",f"http://localhost:{port}/"); r=p.getresponse(); '
        'assert r.status==200, r.status; assert r.read()==b"dummy HTTP response"; '
        'p=http.client.HTTPConnection("127.0.0.1",3128,timeout=5); '
        'p.request("GET","http://blocked.invalid/"); r=p.getresponse(); assert r.status==403,r.status; '
        '\ntry: socket.create_connection(("127.0.0.1",port),timeout=1)\nexcept OSError: pass\nelse: raise AssertionError("network namespace bypass")',
        str(server.server_port)])
    server.shutdown(); server.server_close()
    assert network_probe.returncode == 0, network_probe.stderr
    results.append({'test': 'HTTP proxy permits allowed host, denies other host, direct host connection blocked', 'passed': True})
    settings['network'] = {'allowedDomains': [], 'deniedDomains': [], 'allowAllDomains': True}
    config.write_text(json.dumps(settings))

    # One loaded profile serves other repositories: only the bwrap write roots change.
    other = fixture / 'other-repo'
    (other / 'nested').mkdir(parents=True)
    (other / 'nested/.env').write_text('other dummy secret')
    (other / 'plain.txt').write_text('plain')
    settings['filesystem']['allowWrite'] = [str(other)]
    settings['filesystem']['secretFiles'] = [str(other / 'nested/.env'), str(code / 'config/.env.local')]
    config.write_text(json.dumps(settings))
    regenerated = run([*base, '--print-apparmor-profile'])
    assert regenerated.stdout == generated.stdout, 'profile must not depend on write roots or secret files'
    results.append({'test': 'profile identical for a different repository and secret files', 'passed': True})
    other_probe = run([*base, '--', '/usr/bin/python3', '-c', r'''
import errno, os, pathlib, sys
other = pathlib.Path(sys.argv[1]); code = pathlib.Path(sys.argv[2])
(other / 'plain.txt').write_text('changed')
(other / 'created.txt').write_text('created')
try: (code / 'normal.txt').write_text('x')
except OSError as e: assert e.errno == errno.EROFS, e
else: raise AssertionError('previous repository stayed writable')
for p in [other / 'nested/.env', code / 'config/.env.local']:
    try: p.read_text()
    except PermissionError: pass
    else: raise AssertionError(f'{p} readable at its original path')
assert pathlib.Path('/dev/srt/secrets/0-.env').read_text() == 'other dummy secret'
assert pathlib.Path('/dev/srt/secrets/1-.env.local').read_text() == 'local'
try: pathlib.Path('/dev/srt/secrets/0-.env').write_text('x')
except OSError as e: assert e.errno in (errno.EROFS, errno.EACCES), e
else: raise AssertionError('secret alias writable')
print(pathlib.Path('/proc/self/attr/current').read_text().strip())
''', str(other), str(code)], cwd=other)
    assert other_probe.returncode == 0, other_probe.stdout + other_probe.stderr
    assert other_probe.stdout.strip().endswith('(enforce)')
    assert 'Expanded ' not in other_probe.stderr and 'ripgrep scan' not in other_probe.stderr
    assert (other / 'plain.txt').read_text() == 'changed' and (code / 'normal.txt').read_text() == 'updated'
    results.extend({'test': t, 'passed': True} for t in [
        'new repository writable through mounts with the same profile',
        'previous repository read-only through mounts',
        'secret files unreadable at original paths',
        'secret files readable only at the fixed alias directory',
        'secret alias is read-only',
    ])
    # A worktree checkout creates versioned MCP configuration at root and nested
    # paths. Both a sibling scratch directory and repo/.worktrees must work.
    empty_template = fixture / 'empty-template'
    empty_template.mkdir()
    git = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
           '-c', 'user.name=Sandbox Test', '-c', 'user.email=sandbox@example.invalid']
    initialized = run([*git, 'init', '-q', f'--template={empty_template}'], cwd=other)
    assert initialized.returncode == 0, initialized.stderr
    mcp_paths = ['.mcp.json', 'plugins/example/.mcp.json']
    for rel in mcp_paths:
        path = other / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"mcpServers":{}}\n')
    added = run([*git, 'add', '--', *mcp_paths], cwd=other)
    assert added.returncode == 0, added.stderr
    committed = run([*git, 'commit', '-qm', 'versioned MCP configuration'], cwd=other)
    assert committed.returncode == 0, committed.stderr
    scratch = fixture / 'scratch'
    scratch.mkdir()
    settings['filesystem']['allowWrite'] = [str(other), str(scratch)]
    settings['filesystem']['secretFiles'] = []
    config.write_text(json.dumps(settings))
    for destination in [scratch / 'external', other / '.worktrees/inside']:
        checkout = run([*base, '--', *git, 'worktree', 'add', '--detach', str(destination), 'HEAD'], cwd=other)
        assert checkout.returncode == 0, checkout.stdout + checkout.stderr
        assert (destination / '.git').is_file()
        for rel in mcp_paths:
            assert (destination / rel).read_text() == '{"mcpServers":{}}\n'
        results.append({'test': f'worktree checkout with MCP configuration: {destination.relative_to(fixture)}', 'passed': True})

    settings['filesystem']['secretFiles'] = [str(code / 'private/secret.txt')]
    settings['filesystem']['denyRead'].append('/dev/srt/**')
    config.write_text(json.dumps(settings))
    clash = run([*base, '--', '/bin/sh', '-c', 'touch should-not-run'], cwd=other)
    assert clash.returncode != 0 and not (other / 'should-not-run').exists()
    assert 'denies reading the secret alias path' in clash.stderr
    settings['filesystem']['denyRead'].pop()
    results.append({'test': 'secret alias covered by a deny rule fails closed', 'passed': True})
    settings['filesystem']['secretFiles'] = []
    settings['filesystem']['allowWrite'] = [str(code), str(other / 'glob*')]
    config.write_text(json.dumps(settings))
    glob_write = run([*base, '--', '/bin/sh', '-c', 'touch should-not-run'])
    assert glob_write.returncode != 0 and not (code / 'should-not-run').exists()
    results.append({'test': 'glob write roots fail closed instead of silently scanning', 'passed': True})
    settings['filesystem']['allowWrite'] = [str(code)]
    config.write_text(json.dumps(settings))
    unload(profile)

    complain = fixture / 'complain.apparmor'
    complain.write_text(profile.read_text().replace('flags=(attach_disconnected,mediate_deleted)', 'flags=(complain,attach_disconnected,mediate_deleted)'))
    load(complain)
    wrong_mode = run([*base, '--', '/bin/sh', '-c', 'touch should-not-run'])
    assert wrong_mode.returncode == 126 and not (code / 'should-not-run').exists(), wrong_mode.stderr
    assert 'enforcement verification failed' in wrong_mode.stderr
    results.append({'test': 'complain mode fails closed before workload', 'passed': True})
    unload(complain)
finally:
    for profile in list(loaded):
        unload(profile)
    (fixture / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps({'fixture': str(fixture), 'passed': len(results), 'results': results}, indent=2))
