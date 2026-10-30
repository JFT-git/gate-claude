'use strict';
// Source-match check for the cross-built Windows artifact; not a runtime test.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const repo=path.resolve(__dirname,'../..'),dist=path.resolve(process.argv[2]||path.join(repo,'Windows/dist/Claude Proxy Guard-win32-x64'));
const commit=process.argv[3]||'HEAD';const git=(...args)=>cp.execFileSync('git',['-C',repo,...args]);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const {parseArchive}=require('../../Windows/src/asar.cjs');const bytes=fs.readFileSync(path.join(dist,'resources/app.asar'));const asar=parseArchive(bytes),leaves=[];
(function walk(node,prefix=''){for(const [name,value]of Object.entries(node.files||{})){const file=prefix+name;if(value.files)walk(value,file+'/');else{assert(!value.link&&!value.unpacked);leaves.push(file);}}})(asar.header);
const source=git('ls-tree','-r','--name-only',commit,'Windows/src').toString().trim().split('\n');
for(const file of source)assert.deepEqual(asar.read(file.slice(8)),git('show',commit+':'+file),file);
assert.equal(leaves.length,source.length+2);assert.deepEqual(leaves.filter(x=>!x.startsWith('src/')).sort(),['LICENSE','package.json']);
const product=JSON.parse(asar.read('package.json'));assert.equal(product.version,JSON.parse(git('show',commit+':Windows/package.json')).version);assert.equal(product.scripts,undefined);assert.equal(product.devDependencies,undefined);
const pins=require('../windows/cross-build-pins.json');for(const [name,digest]of Object.entries(pins.sha256))assert.equal(sha(fs.readFileSync(path.join(dist,'resources',name))),digest,name);
assert.deepEqual(fs.readFileSync(path.join(dist,'resources/RuntimeBootstrap.cjs')),git('show',commit+':Resources/RuntimeBootstrap.cjs'));
const docs=git('ls-tree','-r','--name-only',commit,'docs').toString().trim().split('\n');for(const file of ['README.md','SECURITY.md','CHANGELOG.md',...docs])assert.deepEqual(fs.readFileSync(path.join(dist,'Documentation',file)),git('show',commit+':'+file));
let files=0;function inventory(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){assert(!entry.isSymbolicLink());assert(!/^(?:Profile|settings\.json|ip-memory\.json|diagnostics\.json|\.env(?:\..*)?|node_modules|test|Tests|work)$/i.test(entry.name),entry.name);assert(!/\.(?:pem|pfx|p12|key)$/i.test(entry.name),entry.name);if(entry.isDirectory())inventory(path.join(dir,entry.name));else files++;}}inventory(dist);
console.log(JSON.stringify({status:'PASS',mode:'SOURCE_MATCH_NOT_WINDOWS_EXECUTION',sourceCommit:git('rev-parse',commit).toString().trim(),version:product.version,sourceFiles:source.length,packageFiles:files,asarSHA256:sha(bytes),nativeAndCodeToolsPins:'MATCH',testHooksOrProfilesStaged:false}));
