#!/usr/bin/env python3
"""Compare identical policies through legacy mounts and AppArmor, using /bin/true.
Example: python3 test/apparmor-benchmark.py --cwd /home/ubuntu --settings /tmp/home.json --legacy-timeout 60
Requires sudo to load one generated profile. Never alters installed executables.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--cwd', required=True)
parser.add_argument('--settings', required=True)
parser.add_argument('--legacy-timeout', type=float, default=60)
parser.add_argument('--repeat', type=int, default=3)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = Path(tempfile.mkdtemp(prefix='srt-apparmor-benchmark-'))
cfg = json.loads(Path(args.settings).read_text())
cfg['filesystem'].pop('linuxBackend', None)
settings = out / 'settings.json'
settings.write_text(json.dumps(cfg))
base = ['node', str(root / 'dist/cli.js'), '--settings', str(settings)]
env = {k: v for k, v in os.environ.items() if k not in ('SRT_DEBUG', 'NODE_OPTIONS')}
env['SHELL'] = '/bin/bash'

def capture(cmd):
    return subprocess.run(cmd, cwd=args.cwd, env=env, text=True, capture_output=True, check=True, timeout=30)

def measure(cmd, timeout):
    start = time.monotonic()
    p = subprocess.Popen(cmd, cwd=args.cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(p.pid, signal.SIGTERM)
        try: stdout, stderr = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); stdout, stderr = p.communicate()
    result = {'seconds': round(time.monotonic()-start, 4), 'returncode': p.returncode, 'timed_out': timed_out}
    if not timed_out and p.returncode != 0: raise RuntimeError(stderr)
    return result

start = time.monotonic()
policy = capture([*base, '--print-apparmor-profile']).stdout
generation = time.monotonic()-start
profile = out / 'policy.apparmor'
profile.write_text(policy)
start = time.monotonic()
capture(['sudo', '-n', '/usr/sbin/apparmor_parser', '-a', str(profile)])
load_time = time.monotonic()-start
results = []
try:
    legacy_timed_out = False
    for i in range(args.repeat):
        if not legacy_timed_out:
            result = {'backend':'bubblewrap','iteration':i, **measure([*base,'--','/bin/true'],args.legacy_timeout)}
            results.append(result); print(json.dumps(result), flush=True)
            legacy_timed_out = result['timed_out']
        result = {'backend':'apparmor','iteration':i, **measure([*base,'--apparmor','--','/bin/true'],30)}
        results.append(result); print(json.dumps(result), flush=True)
    trace = out / 'apparmor-processes.strace'
    capture(['strace','-f','-e','trace=process','-o',str(trace),*base,'--apparmor','--','/bin/true'])
    execs = [line for line in trace.read_text().splitlines() if 'execve(' in line]
    scanners = [line for line in execs if any('/'+name+'"' in line for name in ('fd','fdfind','rg','find'))]
    assert not scanners, scanners
    result = {'cwd':args.cwd,'generation_seconds':generation,'compile_load_seconds':load_time,'no_scanner_exec_verified':True,'runs':results,'artifacts':str(out)}
    (out/'results.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2),flush=True)
finally:
    capture(['sudo','-n','/usr/sbin/apparmor_parser','-R',str(profile)])
