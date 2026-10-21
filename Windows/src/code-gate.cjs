'use strict';
const net=require('node:net');
const {once}=require('node:events');
const {randomBytes,timingSafeEqual}=require('node:crypto');
const path=require('node:path').win32;
const MAX=16384;
function canonical(value){return typeof value==='string'&&/^[a-z]:\\/i.test(value)&&!/[\x00-\x1f<>"|?*]/.test(value)&&!value.slice(2).includes(':')&&path.normalize(value)===value&&!value.includes('/')}
class CodeGate {
 constructor(config,active){
  this.config=config;this.active=active;this.closed=false;this.sockets=new Set();
  this.name='gate-claude-code-'+randomBytes(16).toString('hex');this.pipe='\\\\.\\pipe\\'+this.name;this.token=randomBytes(32).toString('hex');
 }
 async listen(){
  this.server=net.createServer(socket=>{
   if(this.closed){socket.destroy();return}this.sockets.add(socket);socket.once('close',()=>this.sockets.delete(socket));socket.on('error',()=>{});socket.setTimeout(3000,()=>socket.destroy());
   let input=Buffer.alloc(0),expected;
   socket.on('data',chunk=>{
    if(expected===-1){socket.destroy();return}input=Buffer.concat([input,chunk]);
    if(input.length>MAX+4){socket.destroy();return}
    if(expected===undefined&&input.length>=4){expected=input.readUInt32LE(0);if(expected<1||expected>MAX){socket.destroy();return}}
    if(expected===undefined||input.length<expected+4)return;
    const length=expected;expected=-1;
    let message;try{if(input.length!==length+4)throw Error();message=JSON.parse(input.subarray(4).toString('utf8'))}catch{socket.destroy();return}
    const approved=this.authorize(message);const body=Buffer.from(JSON.stringify({version:1,approved,...approved?{containerSid:this.config.containerSid,relayURL:this.config.relayURL,codeJobName:this.config.codeJobName}: {}}));
    const header=Buffer.alloc(4);header.writeUInt32LE(body.length);socket.end(Buffer.concat([header,body]));
   });
  });
  this.server.maxConnections=32;this.server.on('error',()=>this.close());
  this.server.listen(this.pipe);await once(this.server,'listening');return this;
 }
 authorize(message){
  try{
   if(this.closed||!message||message.version!==1||typeof message.token!=='string'||!/^[a-f0-9]{64}$/.test(message.token)||!timingSafeEqual(Buffer.from(message.token),Buffer.from(this.token)))return false;
   const state=this.active();if(!state||!Number.isSafeInteger(message.parentPid)||message.parentPid!==state.runtimePID)return false;
   const c=this.config;
   if(message.sid!==c.containerSid||message.relayURL!==c.relayURL||message.codeJobName!==c.codeJobName||!/^[a-f0-9]{64}$/.test(message.exeHash||''))return false;
   if(!canonical(message.executable)||!canonical(message.cwd))return false;
   const file=message.executable.toLowerCase();
   if(!c.approved.some(item=>item.path.toLowerCase()===file&&item.sha256===message.exeHash))return false;
   const cwd=message.cwd.toLowerCase(),workspace=path.join(c.stateRoot,'Workspace').toLowerCase(),root=c.stateRoot.toLowerCase();
   return cwd===root||cwd===workspace||cwd.startsWith(workspace+'\\');
  }catch{return false}
 }
 close(){if(this.closed)return;this.closed=true;for(const socket of this.sockets)socket.destroy();this.sockets.clear();try{this.server?.close()}catch{}}
}
module.exports={CodeGate,canonical};
