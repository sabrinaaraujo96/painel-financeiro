/* Backup criptografado: AES-256-GCM, chave derivada da senha com PBKDF2-SHA256. Tudo acontece no aparelho. */
(function(root){
'use strict';
const ITER=600000, FORMAT='painel-financeiro-backup', DATA='painel-financeiro';
const te=new TextEncoder(), td=new TextDecoder();
const subtle=()=>(root.crypto||require('node:crypto').webcrypto).subtle;
const rnd=n=>{const a=new Uint8Array(n);(root.crypto||require('node:crypto').webcrypto).getRandomValues(a);return a;};
function b64(u8){let s='';for(let i=0;i<u8.length;i+=0x8000)s+=String.fromCharCode.apply(null,u8.subarray(i,i+0x8000));return btoa(s);}
function unb64(s){const b=atob(s),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}
async function keyFrom(pw,salt,iter){
  const base=await subtle().importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
  return subtle().deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
const DOC_OK=/^(months\/\d{4}-(0[1-9]|1[0-2])|config\/settings)$/;
function validate(p){
  if(!p||p.app!==DATA||!p.docs||typeof p.docs!=='object') throw new Error('Arquivo não reconhecido.');
  const docs=Object.create(null); let months=0;
  for(const k of Object.keys(p.docs)){
    if(!DOC_OK.test(k)) continue;
    const v=p.docs[k]; if(!v||typeof v!=='object'||Array.isArray(v)) continue;
    docs[k]=JSON.parse(JSON.stringify(v)); if(k.startsWith('months/')) months++;
  }
  if(!months) throw new Error('O arquivo não tem nenhum mês.');
  return {docs,months,exportedAt:p.exportedAt||null};
}
async function encrypt(docs,pw){
  const payload={app:DATA,v:1,exportedAt:new Date().toISOString(),docs};
  const salt=rnd(16), iv=rnd(12), key=await keyFrom(pw,salt,ITER);
  const ct=new Uint8Array(await subtle().encrypt({name:'AES-GCM',iv},key,te.encode(JSON.stringify(payload))));
  return JSON.stringify({app:FORMAT,v:1,cipher:'AES-256-GCM',kdf:'PBKDF2-SHA256',iter:ITER,salt:b64(salt),iv:b64(iv),ct:b64(ct)});
}
/* devolve {encrypted:true} se precisa de senha; ou o conteúdo validado se for arquivo sem criptografia */
function inspect(text){
  let f; try{f=JSON.parse(text);}catch(_){throw new Error('Arquivo não reconhecido.');}
  if(f&&f.app===FORMAT&&f.ct) return {encrypted:true,file:f};
  return {encrypted:false,content:validate(f)};
}
async function decrypt(file,pw){
  if(!file||file.app!==FORMAT||file.cipher!=='AES-256-GCM'||!(file.iter>=100000&&file.iter<=5000000)) throw new Error('Arquivo não reconhecido.');
  let plain;
  try{
    const key=await keyFrom(pw,unb64(file.salt),file.iter);
    plain=await subtle().decrypt({name:'AES-GCM',iv:unb64(file.iv)},key,unb64(file.ct));
  }catch(_){const e=new Error('Senha incorreta ou arquivo danificado.');e.code='bad_password';throw e;}
  return validate(JSON.parse(td.decode(plain)));
}
const api={encrypt,decrypt,inspect,validate,ITER};
if(typeof module!=='undefined'&&module.exports) module.exports=api; else root.Backup=api;
})(typeof globalThis!=='undefined'?globalThis:this);
