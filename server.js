'use strict';
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=Number(process.env.PORT||3000);
const DB_PATH=process.env.DB_PATH||path.join(__dirname,'data','new-life-city.sqlite');
fs.mkdirSync(path.dirname(DB_PATH),{recursive:true});
const db=new DatabaseSync(DB_PATH);
db.exec(`PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,passhash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('buyer','seller','shipper')),balance INTEGER NOT NULL DEFAULT 100000 CHECK(balance>=0),created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY,seller_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL,price INTEGER NOT NULL CHECK(price>0),stock INTEGER NOT NULL CHECK(stock>=0),created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,buyer_id TEXT NOT NULL REFERENCES users(id),seller_id TEXT NOT NULL REFERENCES users(id),shipper_id TEXT REFERENCES users(id),product_id TEXT NOT NULL REFERENCES products(id),product_name TEXT NOT NULL,quantity INTEGER NOT NULL CHECK(quantity>0),unit_price INTEGER NOT NULL,total INTEGER NOT NULL,delivery_fee INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending_seller','awaiting_shipper','delivering','delivered','cancelled')),created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,sender_id TEXT NOT NULL REFERENCES users(id),body TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);
const st=(sql)=>db.prepare(sql);
const getUser=st('SELECT id,username,role,balance,created_at FROM users WHERE id=?');
const getSession=st('SELECT user_id FROM sessions WHERE token_hash=? AND expires>?');
const productView=`SELECT p.id,p.seller_id,p.name,p.price,p.stock,u.username AS seller FROM products p JOIN users u ON u.id=p.seller_id`;
const orderView=`SELECT o.*,b.username AS buyer,s.username AS seller,sh.username AS shipper FROM orders o JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id LEFT JOIN users sh ON sh.id=o.shipper_id`;
const statuses={pending_seller:'Chờ người bán',awaiting_shipper:'Chờ shipper',delivering:'Đang giao',delivered:'Đã giao',cancelled:'Đã hủy'};
function apiError(message,status=400){const e=new Error(message);e.status=status;throw e}
function txn(fn){db.exec('BEGIN IMMEDIATE');try{const result=fn();db.exec('COMMIT');return result}catch(e){db.exec('ROLLBACK');throw e}}
function session(req){const cookie=req.headers.cookie||'';const token=cookie.split(';').map(s=>s.trim()).find(s=>s.startsWith('nlc_session='))?.slice(12);if(!token)return null;const hash=crypto.createHash('sha256').update(token).digest('hex');const found=getSession.get(hash,Date.now());return found?getUser.get(found.user_id):null}
function requireUser(req){return session(req)||apiError('Bạn cần đăng nhập.',401)}
function requireRole(req,role){const u=requireUser(req);if(u.role!==role)apiError('Nghề nghiệp không có quyền thực hiện hành động này.',403);return u}
function send(res,status,data){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data))}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>12000){reject(Object.assign(new Error('Dữ liệu quá dài'),{status:413}));req.destroy()}});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch{reject(Object.assign(new Error('JSON không hợp lệ'),{status:400}))}});req.on('error',reject)})}
const uid=()=>crypto.randomUUID();
function makeCookie(res,u){const tok=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)').run(crypto.createHash('sha256').update(tok).digest('hex'),u.id,Date.now()+30*24*3600*1000);res.setHeader('Set-Cookie',`nlc_session=${tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${process.env.NODE_ENV==='production'?'; Secure':''}`)}
function makePassword(password){const salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(password,salt,64).toString('hex')}
function verifyPassword(password,stored){const [salt,hex]=stored.split(':');if(!salt||!hex)return false;const actual=crypto.scryptSync(password,salt,64);const expected=Buffer.from(hex,'hex');return expected.length===actual.length&&crypto.timingSafeEqual(actual,expected)}
function orderAccess(o,u){return o.buyer_id===u.id||o.seller_id===u.id||o.shipper_id===u.id}
async function api(req,res,url){
 const method=req.method,p=url.pathname;
 if(method!=='GET'){
  if(!req.headers['content-type']?.startsWith('application/json'))apiError('Yêu cầu phải là application/json',415);
  const origin=req.headers.origin;
  if(origin){const allowed=process.env.PUBLIC_ORIGIN||`${req.headers['x-forwarded-proto']||'http'}://${req.headers.host}`;if(origin!==allowed)apiError('Yêu cầu từ trang web khác không được chấp nhận',403)}
 }
 if(p==='/api/register'&&method==='POST'){
  const d=await body(req);const username=String(d.username||'').trim();const password=String(d.password||'');const role=String(d.role||'');
  if(!/^[\p{L}\p{N}_]{3,24}$/u.test(username))apiError('Tên đăng nhập 3–24 ký tự, không có khoảng trắng.');
  if(password.length<8||password.length>128)apiError('Mật khẩu cần 8–128 ký tự.');
  if(!['buyer','seller','shipper'].includes(role))apiError('Vai trò không hợp lệ.');
  const id=uid();try{st('INSERT INTO users(id,username,passhash,role) VALUES(?,?,?,?)').run(id,username,makePassword(password),role)}catch(e){if(String(e).includes('UNIQUE'))apiError('Tên đăng nhập đã được sử dụng.',409);throw e}
  makeCookie(res,{id});return send(res,201,{user:getUser.get(id)});
 }
 if(p==='/api/login'&&method==='POST'){
  const d=await body(req);const username=String(d.username||'').trim();const password=String(d.password||'');const record=st('SELECT * FROM users WHERE username=?').get(username);
  if(!record||!verifyPassword(password,record.passhash))apiError('Sai tên đăng nhập hoặc mật khẩu.',401);
  makeCookie(res,record);return send(res,200,{user:getUser.get(record.id)});
 }
 if(p==='/api/logout'&&method==='POST'){
  const token=(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('nlc_session='))?.slice(12);
  if(token)st('DELETE FROM sessions WHERE token_hash=?').run(crypto.createHash('sha256').update(token).digest('hex'));
  res.setHeader('Set-Cookie','nlc_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');return send(res,200,{ok:true});
 }
 if(p==='/api/me'&&method==='GET')return send(res,200,{user:requireUser(req)});
 if(p==='/api/state'&&method==='GET'){
  const u=requireUser(req);
  const products=st(productView+' WHERE p.stock>0 ORDER BY p.created_at DESC LIMIT 100').all();
  const orders=st(orderView+` WHERE o.buyer_id=? OR o.seller_id=? OR o.shipper_id=? OR (o.status='awaiting_shipper' AND ?='shipper') ORDER BY o.created_at DESC LIMIT 150`).all(u.id,u.id,u.id,u.role);
  return send(res,200,{user:u,products,orders,statuses});
 }
 if(p==='/api/products'&&method==='POST'){
  const u=requireRole(req,'seller');const d=await body(req);const name=String(d.name||'').trim();const price=Number(d.price),stock=Number(d.stock);
  if(name.length<2||name.length>80||!Number.isSafeInteger(price)||price<=0||price>100000000||!Number.isSafeInteger(stock)||stock<0||stock>100000)apiError('Tên, giá hoặc tồn kho không hợp lệ.');
  st('INSERT INTO products(id,seller_id,name,price,stock) VALUES(?,?,?,?,?)').run(uid(),u.id,name,price,stock);return send(res,201,{ok:true});
 }
 if(p==='/api/orders'&&method==='POST'){
  const u=requireRole(req,'buyer');const d=await body(req),quantity=Number(d.quantity||1),productId=String(d.productId||'');
  if(!Number.isSafeInteger(quantity)||quantity<1||quantity>30)apiError('Số lượng không hợp lệ.');
  const id=txn(()=>{
   const product=st('SELECT * FROM products WHERE id=?').get(productId);if(!product)apiError('Không tìm thấy sản phẩm.',404);
   if(product.stock<quantity)apiError('Sản phẩm không đủ tồn kho.');
   const fee=30,total=product.price*quantity,cost=total+fee;
   if(!Number.isSafeInteger(cost))apiError('Giá trị đơn không hợp lệ.');
   if(st('UPDATE users SET balance=balance-? WHERE id=? AND balance>=?').run(cost,u.id,cost).changes!==1)apiError('Không đủ NL$ để thanh toán.');
   if(st('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(quantity,productId,quantity).changes!==1)apiError('Sản phẩm hết hàng.');
   const orderId=uid();st(`INSERT INTO orders(id,buyer_id,seller_id,product_id,product_name,quantity,unit_price,total,delivery_fee,status) VALUES(?,?,?,?,?,?,?,?,?,'pending_seller')`).run(orderId,u.id,product.seller_id,product.id,product.name,quantity,product.price,total,fee);return orderId;
  });return send(res,201,{id});
 }
 const action=p.match(/^\/api\/orders\/([a-f0-9-]+)\/(pack|accept|deliver|cancel)$/);
 if(action&&method==='POST'){
  const u=requireUser(req),id=action[1],kind=action[2];
  txn(()=>{
   const o=st('SELECT * FROM orders WHERE id=?').get(id);if(!o)apiError('Không tìm thấy đơn.',404);
   if(kind==='pack'){
    if(u.role!=='seller'||o.seller_id!==u.id||o.status!=='pending_seller')apiError('Không thể đóng gói đơn này.',403);
    st(`UPDATE orders SET status='awaiting_shipper',updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(id);
   }else if(kind==='accept'){
    if(u.role!=='shipper'||o.status!=='awaiting_shipper')apiError('Đơn đã có người nhận hoặc chưa đóng gói.',409);
    st(`UPDATE orders SET status='delivering',shipper_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='awaiting_shipper'`).run(u.id,id);
   }else if(kind==='deliver'){
    if(u.role!=='shipper'||o.shipper_id!==u.id||o.status!=='delivering')apiError('Bạn không thể xác nhận đơn này.',403);
    st(`UPDATE orders SET status='delivered',updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(id);
    st('UPDATE users SET balance=balance+? WHERE id=?').run(o.total,o.seller_id);
    st('UPDATE users SET balance=balance+? WHERE id=?').run(o.delivery_fee,u.id);
   }else if(kind==='cancel'){
    if(u.role!=='buyer'||o.buyer_id!==u.id||o.status!=='pending_seller')apiError('Chỉ hủy được đơn chưa đóng gói của bạn.',403);
    st(`UPDATE orders SET status='cancelled',updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(id);
    st('UPDATE users SET balance=balance+? WHERE id=?').run(o.total+o.delivery_fee,u.id);
    st('UPDATE products SET stock=stock+? WHERE id=?').run(o.quantity,o.product_id);
   }
  });return send(res,200,{ok:true});
 }
 const chat=p.match(/^\/api\/orders\/([a-f0-9-]+)\/messages$/);
 if(chat){const u=requireUser(req);const o=st('SELECT * FROM orders WHERE id=?').get(chat[1]);if(!o)apiError('Đơn không tồn tại.',404);
  if(!orderAccess(o,u))apiError('Không có quyền xem tin nhắn đơn này.',403);
  if(method==='GET')return send(res,200,{messages:st('SELECT m.id,m.body,m.created_at,u.username AS sender FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.order_id=? ORDER BY m.created_at ASC LIMIT 100').all(o.id)});
  if(method==='POST'){const d=await body(req),value=String(d.text||'').trim();if(value.length<1||value.length>500)apiError('Tin nhắn phải có 1–500 ký tự.');st('INSERT INTO messages(id,order_id,sender_id,body) VALUES(?,?,?,?)').run(uid(),o.id,u.id,value);return send(res,201,{ok:true})}
 }
 apiError('Đường dẫn API không tồn tại.',404);
}
const root=path.join(__dirname,'public');
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.png':'image/png','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/'))return await api(req,res,url);
 if(req.method!=='GET')return send(res,405,{error:'Method not allowed'});
 const rel=url.pathname==='/'?'index.html':url.pathname.replace(/^\/+/, '');const file=path.resolve(root,rel);
 if(!(file===root||file.startsWith(root+path.sep))||!fs.existsSync(file)||!fs.statSync(file).isFile())return send(res,404,{error:'Không tìm thấy trang'});
 res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Cache-Control':'no-cache','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"});fs.createReadStream(file).pipe(res);
}catch(e){console.error('Request error:',e.message);if(!res.headersSent)send(res,e.status||500,{error:e.status?e.message:'Máy chủ gặp lỗi. Vui lòng thử lại.'})}});
server.listen(PORT,'0.0.0.0',()=>console.log(`New Life City running on http://localhost:${PORT} — database: ${DB_PATH}`));
