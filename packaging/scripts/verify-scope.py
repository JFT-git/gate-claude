#!/usr/bin/env python3
"""Scope gate for this presentation/packaging release, against its engine baseline."""
import pathlib,subprocess,hashlib,json
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE='6d5ede249b9992ae8222839fbd5b704d579275fb'
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args])
files=git('ls-tree','-r','--name-only',BASE).decode().splitlines()
protected=[p for p in files if p.startswith(('Windows/native/','Windows/src/','Resources/','Source/')) and not p.startswith('Windows/src/ui/') and p not in ['Windows/src/main.cjs','Windows/src/preload.cjs','Source/App.swift']]
fail=[]
for p in protected:
 if (ROOT/p).read_bytes()!=git('show',BASE+':'+p):fail.append(p)
marker=b'private struct Surface<Content: View>'
if (ROOT/'Source/App.swift').read_bytes().split(marker)[0]!=git('show',BASE+':Source/App.swift').split(marker)[0]:fail.append('Source/App.swift: GuardModel')
if fail:raise SystemExit('Engine scope violation: '+', '.join(fail))
print(json.dumps({'status':'PASS','baseline':BASE,'protectedFiles':len(protected),'macOSModel':'BYTE_IDENTICAL','note':'main/preload IPC, views, documentation and packaging require separate review'}))
