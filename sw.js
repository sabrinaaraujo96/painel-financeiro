/* Só guarda os arquivos do app para abrir offline. Nunca toca nos dados (IndexedDB). */
const CACHE='painel-v1.1.1';
const FILES=['./','index.html','backup.js','store.js','manifest.webmanifest','icon-192.png','icon-512.png','apple-touch-icon.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(FILES)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE&&k.startsWith('painel-')).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  const r=e.request; if(r.method!=='GET'||new URL(r.url).origin!==location.origin) return;
  e.respondWith(caches.open(CACHE).then(async c=>{
    const hit=await c.match(r,{ignoreSearch:true});
    const net=fetch(r).then(res=>{if(res&&res.ok)c.put(r,res.clone());return res;}).catch(()=>null);
    if(hit){e.waitUntil(net);return hit;}
    return (await net)||(await c.match('index.html'))||Response.error();
  }));
});
