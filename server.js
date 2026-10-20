// Private QA server. Page is stored AES-256-GCM encrypted; key only in env SITE_KEY. Basic Auth via SITE_PASSWORD. noindex.
'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PASS=process.env.SITE_PASSWORD||'',USER=process.env.SITE_USER||'qa',PORT=process.env.PORT||10000;
const EXPIRES=Date.parse(process.env.EXPIRES_AT||'')||0;
let page=null;
try{const raw=fs.readFileSync(path.join(__dirname,'page.enc')),key=Buffer.from(process.env.SITE_KEY||'','hex');
 const iv=raw.subarray(0,12),tag=raw.subarray(raw.length-16),data=raw.subarray(12,raw.length-16);
 const d=crypto.createDecipheriv('aes-256-gcm',key,iv);d.setAAD(Buffer.from('shalvata-v847'));d.setAuthTag(tag);page=Buffer.concat([d.update(data),d.final()]);
}catch(e){console.log('page not decrypted')}
const eq=(a,b)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y)};
const base={'X-Robots-Tag':'noindex, nofollow, noarchive','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Cache-Control':'no-store','Permissions-Policy':'microphone=(self), camera=(self), geolocation=()','Strict-Transport-Security':'max-age=31536000'};
http.createServer((req,res)=>{
 if(req.url==='/healthz'){res.writeHead(page?200:503,{'Content-Type':'text/plain',...base});return res.end(page?'ok':'no page')}
 if(EXPIRES&&Date.now()>EXPIRES){res.writeHead(410,{'Content-Type':'text/plain',...base});return res.end('expired')}
 if(!PASS||!page){res.writeHead(503,{'Content-Type':'text/plain',...base});return res.end('not configured')}
 const h=req.headers.authorization||'';let ok=false;
 if(h.startsWith('Basic ')){const [u,...p]=Buffer.from(h.slice(6),'base64').toString('utf8').split(':');ok=eq(u||'',USER)&&eq(p.join(':'),PASS)}
 if(!ok){res.writeHead(401,{'WWW-Authenticate':'Basic realm="private QA", charset="UTF-8"','Content-Type':'text/plain',...base});return res.end('auth required')}
 const u=req.url.split('?')[0];
 if(u==='/robots.txt'){res.writeHead(200,{'Content-Type':'text/plain',...base});return res.end('User-agent: *\nDisallow: /\n')}
 if(u!=='/'&&u!=='/index.html'){res.writeHead(404,{'Content-Type':'text/plain',...base});return res.end('not found')}
 res.writeHead(200,{'Content-Type':'text/html; charset=utf-8',...base});res.end(page);
}).listen(PORT,()=>console.log('private QA listening'));
