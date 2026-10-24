#!/usr/bin/env python3
"""Accept only the app's expected executables/signature and exact source resources."""
import sys,pathlib,zipfile,json
root=pathlib.Path(__file__).resolve().parents[2]
expected={
 'Info.plist':root/'Info.plist',
 'Resources/RuntimeBootstrap.cjs':root/'Resources/RuntimeBootstrap.cjs',
 'Resources/AppIcon.icns':root/'AppIcon.icns',
}
for p in ['README.md','SECURITY.md','CHANGELOG.md',*[x.relative_to(root).as_posix() for x in (root/'docs').rglob('*') if x.is_file()]]:
 expected['Resources/Documentation/'+p]=root/p
for p in ['MacOS/ClaudeProxyGuard','MacOS/GuardHost','MacOS/GuardDrop','_CodeSignature/CodeResources']:
 expected[p]=root/'Claude Proxy Guard.app/Contents'/p
seen=set()
with zipfile.ZipFile(sys.argv[1]) as z:
 if z.testzip() is not None:raise SystemExit('ZIP CRC failure')
 for name in z.namelist():
  if name.endswith('/'):continue
  prefix='Claude Proxy Guard.app/Contents/'
  if not name.startswith(prefix):raise SystemExit('Unexpected archive path: '+name)
  rel=name[len(prefix):]
  if rel not in expected or rel in seen:raise SystemExit('Unexpected or duplicate entry: '+rel)
  if z.read(name)!=expected[rel].read_bytes():raise SystemExit('Byte mismatch: '+rel)
  seen.add(rel)
if seen!=set(expected):raise SystemExit('Missing expected bundle files')
print(json.dumps({'status':'PASS','regularFiles':len(seen),'resourcesAndDocuments':'BYTE_MATCH','appleDoubleOrUnexpectedFiles':0,'runtimeTest':'NOT_RUN_BY_THIS_CHECK'}))
