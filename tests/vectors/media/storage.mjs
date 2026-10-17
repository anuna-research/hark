// Test-only HTTPS object store; contains no real credentials or persistent data.
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
let bytes=Buffer.alloc(0);
const server=https.createServer({key:readFileSync(new URL('./localhost-key.pem',import.meta.url)),cert:readFileSync(new URL('./localhost-cert.pem',import.meta.url))},async(req,res)=>{
  if(req.url==='/redirect'){res.writeHead(302,{location:'/object'});res.end();return;}
  if(req.url==='/oversize'){res.writeHead(200);res.write(bytes);res.end(Buffer.from([0]));return;}
  if(req.url==='/corrupt'){const b=Buffer.from(bytes);if(b.length)b[b.length-1]^=1;res.end(b);return;}
  if(req.method==='PUT'){
    const chunks=[];for await(const chunk of req)chunks.push(chunk);const next=Buffer.concat(chunks);
    if(req.headers['x-amz-checksum-sha256']!==createHash('sha256').update(next).digest('base64')||req.headers['content-type']!=='application/octet-stream'){res.writeHead(400);res.end();return;}
    bytes=next;res.end();return;
  }
  if(req.method==='GET'){res.end(bytes);return;}
  res.writeHead(405);res.end();
});
server.listen(0,'127.0.0.1',()=>process.stdout.write(String(server.address().port)+'\n'));
