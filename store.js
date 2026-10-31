/* Banco local (IndexedDB). Mesma interface que o painel já usa: doc(path).update/set/onSnapshot e collection(name).onSnapshot.
   As atualizações do app nunca mexem aqui: o esquema só cria o que falta, nunca apaga. */
(function(root){
'use strict';
const NAME='painel-financeiro', VER=1;
const mem=new Map(); const subs=[]; let idb=null, persistent=false;
function open(){
  return new Promise(res=>{
    if(!root.indexedDB){res(null);return;}
    let rq; try{rq=root.indexedDB.open(NAME,VER);}catch(_){res(null);return;}
    rq.onupgradeneeded=()=>{const d=rq.result; if(!d.objectStoreNames.contains('docs')) d.createObjectStore('docs',{keyPath:'path'}); if(!d.objectStoreNames.contains('snapshots')) d.createObjectStore('snapshots',{keyPath:'id'});};
    rq.onsuccess=()=>res(rq.result); rq.onerror=()=>res(null); rq.onblocked=()=>res(null);
  });
}
const tx=(store,mode,fn)=>new Promise((ok,no)=>{const t=idb.transaction(store,mode);const r=fn(t.objectStore(store));t.oncomplete=()=>ok(r&&r.result);t.onerror=()=>no(t.error);t.onabort=()=>no(t.error);});
async function init(){
  idb=await open();
  if(idb){
    const rows=await tx('docs','readonly',s=>s.getAll());
    for(const r of rows) mem.set(r.path,r.data);
    try{ if(navigator.storage&&navigator.storage.persist) persistent=await navigator.storage.persist(); }catch(_){}
  }
  return !!idb;
}
const clone=x=>JSON.parse(JSON.stringify(x));
function snapOf(col){
  const docs=[]; for(const [p,d] of mem) if(p.startsWith(col+'/')&&p.split('/').length===2) docs.push({id:p.split('/')[1],data:()=>clone(d)});
  return {docs};
}
function notify(paths){ for(const s of subs){ if(paths===null||paths.some(p=>s.match(p))) s.fire(); } }
async function put(path,data){ mem.set(path,data); if(idb) await tx('docs','readwrite',s=>s.put({path,data})); notify([path]); }
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
/* substitui tudo; antes guarda um ponto de restauração com os dados atuais */
async function replaceAll(docs){
  const before=dump();
  if(idb&&Object.keys(before).length){
    await tx('snapshots','readwrite',s=>s.put({id:'last-import',at:new Date().toISOString(),docs:before}));
  }
  const keep=mem.get('config/backup');
  if(idb){
    await new Promise((ok,no)=>{
      const t=idb.transaction('docs','readwrite'); const s=t.objectStore('docs'); s.clear();
      for(const p of Object.keys(docs)) s.put({path:p,data:docs[p]});
      if(keep) s.put({path:'config/backup',data:keep});
      t.oncomplete=ok; t.onerror=()=>no(t.error); t.onabort=()=>no(t.error);
    });
  }
  mem.clear(); for(const p of Object.keys(docs)) mem.set(p,clone(docs[p])); if(keep) mem.set('config/backup',keep);
  notify(null);
}
async function restorePoint(){ if(!idb) return null; return tx('snapshots','readonly',s=>s.get('last-import')); }
async function persisted(){ try{ return navigator.storage&&navigator.storage.persisted?await navigator.storage.persisted():persistent; }catch(_){return false;} }
const api={init,doc,collection,dump,replaceAll,restorePoint,persisted,available:()=>!!idb};
if(typeof module!=='undefined'&&module.exports) module.exports=api; else root.LocalStore=api;
})(typeof globalThis!=='undefined'?globalThis:this);
