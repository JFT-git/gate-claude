#!/usr/bin/env python3
"""Hash only explicitly allowlisted distributables in a dedicated output folder."""
import argparse,hashlib,json,pathlib,re
p=argparse.ArgumentParser();p.add_argument('directory',type=pathlib.Path);p.add_argument('--commit',required=True);a=p.parse_args()
if not re.fullmatch('[0-9a-f]{40}',a.commit):raise SystemExit('Expected full source commit')
patterns=[r'ClaudeProxyGuard-Windows-\d+\.\d+\.\d+-x64(?:-Setup\.exe|\.zip)',r'ClaudeProxyGuard-macOS-\d+\.\d+\.\d+-universal\.(?:zip|dmg)',r'(?:macos|windows)-build-status\.json',r'(?:ui|release)-validation\.json']
files=[]
for f in sorted(a.directory.iterdir()):
 if f.is_symlink() or not f.is_file():raise SystemExit('Only regular artifacts accepted: '+f.name)
 if f.name in ['release-manifest.json','SHA256SUMS.txt'] or f.name.endswith('.sha256'):continue
 if not any(re.fullmatch(x,f.name) for x in patterns):raise SystemExit('Not allowlisted: '+f.name)
 h=hashlib.sha256()
 with f.open('rb') as stream:
  for chunk in iter(lambda:stream.read(4*1024*1024),b''):h.update(chunk)
 files.append({'name':f.name,'size':f.stat().st_size,'sha256':h.hexdigest()})
if not files:raise SystemExit('No artifacts')
(a.directory/'release-manifest.json').write_text(json.dumps({'schema':1,'sourceCommit':a.commit,'publisherSignature':'NOT_CONFIGURED','files':files},indent=2)+'\n')
(a.directory/'SHA256SUMS.txt').write_text(''.join(f"{f['sha256']}  {f['name']}\n" for f in files))
print(json.dumps({'artifacts':len(files),'sourceCommit':a.commit}))
