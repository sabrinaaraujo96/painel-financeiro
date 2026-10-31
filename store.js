/* Banco local (IndexedDB) com criptografia por PIN.
   - Uma chave aleatória (DEK) criptografa cada documento (AES-256-GCM). A DEK fica guardada "embrulhada" por uma chave derivada do PIN (PBKDF2-SHA256, 600 mil rodadas).
   - O PIN nunca é gravado. Acertar o PIN = conseguir abrir a DEK.
   - Mesma interface de antes (doc/collection/onSnapshot). Atualizações do app nunca apagam dados: o esquema só cria o que falta. */
(function(root){
'use strict';
const NAME='painel-financeiro', VER=2, ITER=600000;
const te=new TextEncoder(), td=new TextDecoder();
const subtle=()=>root.crypto.subtle;
const rnd=n=>{const a=new Uint8Array(n);root.crypto.getRandomValues(a);return a;};
const mem=new Map(), subs=[]; let idb=null, persistent=false, dek=null, lockMeta=null, legacy=false;
const clone=x=>JSON.parse(JSON.stringify(x));

function open(){
  return new Promise(res=>{
    if(!root.indexedDB){res(null);return;}
    let rq; try{rq=root.indexedDB.open(NAME,VER);}catch(_){res(null);return;}
    rq.onupgradeneeded=()=>{const d=rq.result;
      if(!d.objectStoreNames.contains('docs')) d.createObjectStore('docs',{keyPath:'path'});
      if(!d.objectStoreNames.contains('snapshots')) d.createObjectStore('snapshots',{keyPath:'id'});
      if(!d.objectStoreNames.contains('meta')) d.createObjectStore('meta',{keyPath:'k'});};
    rq.onsuccess=()=>res(rq.result); rq.onerror=()=>res(null); rq.onblocked=()=>res(null);
  });
}
const tx=(store,mode,fn)=>new Promise((ok,no)=>{const t=idb.transaction(store,mode);const r=fn(t.objectStore(store));t.oncomplete=()=>ok(r&&r.result);t.onerror=()=>no(t.error);t.onabort=()=>no(t.error);});

/* criptografia */
async function kekFrom(pin,salt,iter){
  const base=await subtle().importKey('raw',te.encode(pin),'PBKDF2',false,['deriveKey']);
  return subtle().deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
const aes=(key,iv,data,aad,dec)=>subtle()[dec?'decrypt':'encrypt']({name:'AES-GCM',iv,additionalData:aad},key,data);
const importDek=raw=>subtle().importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
const AAD_DEK=te.encode('dek');
async function encDoc(path,data){const iv=rnd(12);return {iv,ct:await aes(dek,iv,te.encode(JSON.stringify(data)),te.encode(path))};}
async function decDoc(path,enc){return JSON.parse(td.decode(await aes(dek,enc.iv,enc.ct,te.encode(path),true)));}
async function unwrapRaw(pin){
  const k=await kekFrom(pin,lockMeta.salt,lockMeta.iter);
  return new Uint8Array(await aes(k,lockMeta.iv,lockMeta.wrapped,AAD_DEK,true));
}
async function saveMeta(m){lockMeta=m;await tx('meta','readwrite',s=>s.put(m));}
async function failed(){
  const fails=(lockMeta.fails||0)+1;
  const wait=fails>=5?Math.min(3600,30*Math.pow(2,fails-5)):0;
  await saveMeta(Object.assign({},lockMeta,{fails,until:wait?Date.now()+wait*1000:0}));
  return {ok:false,fails,wait};
}
const waitLeft=()=>lockMeta&&lockMeta.until>Date.now()?Math.ceil((lockMeta.until-Date.now())/1000):0;

async function init(){
  idb=await open();
  if(!idb) return {ok:false};
  try{ if(navigator.storage&&navigator.storage.persist) persistent=await navigator.storage.persist(); }catch(_){}
  lockMeta=(await tx('meta','readonly',s=>s.get('lock')))||null;
  if(!lockMeta){
    const rows=await tx('docs','readonly',s=>s.getAll());
    for(const r of rows) if(r.data) mem.set(r.path,r.data);
    legacy=mem.size>0;
    return {ok:true,state:'setup',legacy};
  }
  return {ok:true,state:'locked',wait:waitLeft(),fails:lockMeta.fails||0};
}
/* cria o PIN e criptografa tudo o que já existe, de uma vez só */
async function setupPin(pin){
  if(lockMeta) throw new Error('already_protected');
  const raw=rnd(32), salt=rnd(16), iv=rnd(12);
  const wrapped=await aes(await kekFrom(pin,salt,ITER),iv,raw,AAD_DEK);
  dek=await importDek(raw);
  const recs=[];
  for(const [p,d] of mem){
    const enc=await encDoc(p,d);
    if(JSON.stringify(await decDoc(p,enc))!==JSON.stringify(d)) throw new Error('verify_failed');
    recs.push({path:p,enc});
  }
  const meta={k:'lock',v:1,salt,iter:ITER,iv,wrapped,fails:0,until:0};
  await new Promise((ok,no)=>{
    const t=idb.transaction(['docs','snapshots','meta'],'readwrite');
    const d=t.objectStore('docs'); d.clear(); recs.forEach(r=>d.put(r));
    t.objectStore('snapshots').clear(); t.objectStore('meta').put(meta);
    t.oncomplete=ok; t.onerror=()=>no(t.error); t.onabort=()=>no(t.error);
  });
  lockMeta=meta; legacy=false;
}
async function unlock(pin){
  if(!lockMeta) throw new Error('no_lock');
  const w=waitLeft(); if(w) return {ok:false,wait:w,fails:lockMeta.fails||0};
  let raw;
  try{ raw=await unwrapRaw(pin); }catch(_){ return failed(); }
  dek=await importDek(raw);
  const rows=await tx('docs','readonly',s=>s.getAll()); mem.clear(); const bad=[];
  for(const r of rows){ try{ mem.set(r.path,r.enc?await decDoc(r.path,r.enc):r.data); }catch(_){ bad.push(r.path); } }
  if(lockMeta.fails||lockMeta.until) await saveMeta(Object.assign({},lockMeta,{fails:0,until:0}));
  return {ok:true,bad};
}
async function verifyPin(pin){
  const w=waitLeft(); if(w) return {ok:false,wait:w,fails:lockMeta.fails||0};
  try{ await unwrapRaw(pin); }catch(_){ return failed(); }
  if(lockMeta.fails||lockMeta.until) await saveMeta(Object.assign({},lockMeta,{fails:0,until:0}));
  return {ok:true};
}
async function changePin(oldPin,newPin){
  const raw=await unwrapRaw(oldPin);
  const salt=rnd(16), iv=rnd(12);
  const wrapped=await aes(await kekFrom(newPin,salt,ITER),iv,raw,AAD_DEK);
  await saveMeta(Object.assign({},lockMeta,{salt,iv,wrapped,iter:ITER,fails:0,until:0}));
}
function lock(){ dek=null; mem.clear(); }
async function wipe(){
  await new Promise((ok,no)=>{const t=idb.transaction(['docs','snapshots','meta'],'readwrite');
    ['docs','snapshots','meta'].forEach(n=>t.objectStore(n).clear()); t.oncomplete=ok; t.onerror=()=>no(t.error); t.onabort=()=>no(t.error);});
  mem.clear(); dek=null; lockMeta=null; legacy=false; notify(null);
}

/* dados */
function snapOf(col){
  const docs=[]; for(const [p,d] of mem) if(p.startsWith(col+'/')&&p.split('/').length===2) docs.push({id:p.split('/')[1],data:()=>clone(d)});
  return {docs};
}
function notify(paths){ for(const s of subs.slice()){ if(paths===null||paths.some(p=>s.match(p))) s.fire(); } }
async function put(path,data){
  if(idb){
    if(lockMeta){ if(!dek) throw new Error('locked'); const enc=await encDoc(path,data); await tx('docs','readwrite',s=>s.put({path,enc})); }
    else await tx('docs','readwrite',s=>s.put({path,data}));
  }
  mem.set(path,data); notify([path]);
}
function doc(path){
  return {
    update:async patch=>{const cur=mem.get(path); if(!cur) throw new Error('doc_not_found'); await put(path,Object.assign({},clone(cur),clone(patch)));},
    set:async data=>{await put(path,clone(data));},
    onSnapshot:(cb)=>{const s={match:p=>p===path,fire:()=>{const d=mem.get(path);cb({exists:!!d,data:()=>d?clone(d):undefined});}};subs.push(s);s.fire();return()=>{const i=subs.indexOf(s);if(i>=0)subs.splice(i,1);};}
  };
}
function collection(col){
  return {onSnapshot:(cb)=>{const s={match:p=>p.startsWith(col+'/'),fire:()=>cb(snapOf(col))};subs.push(s);s.fire();return()=>{const i=subs.indexOf(s);if(i>=0)subs.splice(i,1);};}};
}
const EXPORT_SKIP=new Set(['config/backup']);
function dump(){const o={}; for(const [p,d] of mem) if(!EXPORT_SKIP.has(p)) o[p]=clone(d); return o;}
/* substitui tudo; antes guarda (criptografado) um ponto de restauração com os dados atuais */
async function replaceAll(docs){
  if(lockMeta&&!dek) throw new Error('locked');
  const before=dump();
  const keep=mem.get('config/backup');
  const recs=[];
  for(const p of Object.keys(docs)) recs.push(lockMeta?{path:p,enc:await encDoc(p,docs[p])}:{path:p,data:docs[p]});
  if(keep) recs.push(lockMeta?{path:'config/backup',enc:await encDoc('config/backup',keep)}:{path:'config/backup',data:keep});
  let snap=null;
  if(Object.keys(before).length) snap=lockMeta?{id:'last-import',at:new Date().toISOString(),enc:await encDoc('snapshot',before)}:{id:'last-import',at:new Date().toISOString(),docs:before};
  if(idb){
    await new Promise((ok,no)=>{
      const t=idb.transaction(['docs','snapshots'],'readwrite'); const s=t.objectStore('docs'); s.clear(); recs.forEach(r=>s.put(r));
      if(snap) t.objectStore('snapshots').put(snap);
      t.oncomplete=ok; t.onerror=()=>no(t.error); t.onabort=()=>no(t.error);
    });
  }
  mem.clear(); for(const p of Object.keys(docs)) mem.set(p,clone(docs[p])); if(keep) mem.set('config/backup',keep);
  notify(null);
}
async function restorePoint(){
  if(!idb) return null;
  const r=await tx('snapshots','readonly',s=>s.get('last-import')); if(!r) return null;
  if(r.enc){ if(!dek) return null; try{return {at:r.at,docs:await decDoc('snapshot',r.enc)};}catch(_){return null;} }
  return {at:r.at,docs:r.docs};
}
async function persisted(){ try{ return navigator.storage&&navigator.storage.persisted?await navigator.storage.persisted():persistent; }catch(_){return false;} }
const api={init,setupPin,unlock,verifyPin,changePin,lock,wipe,refresh:()=>notify(null),hasLock:()=>!!lockMeta,isUnlocked:()=>!!dek,hasLegacy:()=>legacy,
  doc,collection,dump,replaceAll,restorePoint,persisted,available:()=>!!idb};
if(typeof module!=='undefined'&&module.exports) module.exports=api; else root.LocalStore=api;
})(typeof globalThis!=='undefined'?globalThis:this);
