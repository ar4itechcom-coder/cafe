const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const path=require("path");
const crypto=require("crypto");
const app=express(), PORT=process.env.PORT||3000;
const db=new Database(path.join(__dirname,"data","anbar.db"));
db.pragma("journal_mode=WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,description TEXT,price REAL NOT NULL,image TEXT,category TEXT NOT NULL,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,order_no TEXT UNIQUE NOT NULL,user_id INTEGER,name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,payment TEXT NOT NULL DEFAULT 'cod',status TEXT NOT NULL DEFAULT 'new',subtotal REAL NOT NULL,delivery REAL NOT NULL,total REAL NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER,product_id INTEGER,name TEXT NOT NULL,price REAL NOT NULL,qty INTEGER NOT NULL);
`);
const count=db.prepare("SELECT COUNT(*) c FROM products").get().c;
if(!count){
 const seed=[
 ["مجبوس دجاج","أرز مبهر مع دجاج طري وتتبيلة كويتية.",2.750,"https://images.unsplash.com/photo-1601050690597-df0568f70950?auto=format&fit=crop&w=800&q=85","main"],
 ["مجبوس لحم","لحم طري مع أرز عطري وتوابل عنبر.",3.750,"https://images.unsplash.com/photo-1544025162-d76694265947?auto=format&fit=crop&w=800&q=85","main"],
 ["مرقوق كويتي","طبق كويتي منزلي غني بالخضار واللحم.",3.250,"https://images.unsplash.com/photo-1547592180-85f173990554?auto=format&fit=crop&w=800&q=85","main"],
 ["تشريب دجاج","خبز رقاق مع مرق الدجاج والخضار.",2.500,"https://images.unsplash.com/photo-1601050690117-94f5f6fa8bd7?auto=format&fit=crop&w=800&q=85","main"],
 ["أرز بالزعفران","أرز عطري بالزعفران والمكسرات.",1.750,"https://images.unsplash.com/photo-1512058564366-18510be2db19?auto=format&fit=crop&w=800&q=85","rice"],
 ["هريس كويتي","هريس ناعم بوصفة كويتية تقليدية.",2.250,"https://images.unsplash.com/photo-1547592180-85f173990554?auto=format&fit=crop&w=800&q=85","main"],
 ["لقيمات","لقيمات ذهبية مع دبس التمر.",1.250,"https://images.unsplash.com/photo-1551024506-0bccd828d307?auto=format&fit=crop&w=800&q=85","dessert"],
 ["كرك","شاي كرك ساخن بنكهة الهيل.",0.750,"https://images.unsplash.com/photo-1576092768241-dec231879fc3?auto=format&fit=crop&w=800&q=85","drinks"]
 ];
 const ins=db.prepare("INSERT INTO products(name,description,price,image,category) VALUES(?,?,?,?,?)");
 db.transaction(()=>seed.forEach(x=>ins.run(...x)))();
}
const adminEmail=process.env.ADMIN_EMAIL||"admin@anbar.local", adminPass=process.env.ADMIN_PASSWORD||"Admin@12345";
if(!db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)){
 db.prepare("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)").run("مدير عنبر",adminEmail,bcrypt.hashSync(adminPass,12),"admin");
}
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({secret:process.env.SESSION_SECRET||"change-this-secret",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",maxAge:1000*60*60*24*7}}));
app.use(express.static(path.join(__dirname,"public")));
const auth=(req,res,next)=>{if(!req.session.user)return res.status(401).json({error:"يجب تسجيل الدخول"});next()};
const admin=(req,res,next)=>{if(!req.session.user||req.session.user.role!=="admin")return res.status(403).json({error:"غير مصرح"});next()};
app.get("/api/products",(req,res)=>res.json(db.prepare("SELECT * FROM products WHERE active=1 ORDER BY id DESC").all()));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));
app.post("/api/register",(req,res)=>{
 const {name,email,password}=req.body;if(!name||!email||!password||password.length<8)return res.status(400).json({error:"أدخل البيانات وكلمة مرور لا تقل عن 8 أحرف"});
 try{const info=db.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").run(name,email.toLowerCase(),bcrypt.hashSync(password,12));const user={id:info.lastInsertRowid,name,email:email.toLowerCase(),role:"customer"};req.session.user=user;res.json({user})}catch(e){res.status(409).json({error:"البريد الإلكتروني مستخدم بالفعل"})}
});
app.post("/api/login",(req,res)=>{const u=db.prepare("SELECT * FROM users WHERE email=?").get(String(req.body.email||"").toLowerCase());if(!u||!bcrypt.compareSync(req.body.password||"",u.password))return res.status(401).json({error:"البريد أو كلمة المرور غير صحيحة"});const user={id:u.id,name:u.name,email:u.email,role:u.role};req.session.user=user;res.json({user})});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.post("/api/forgot",(req,res)=>res.json({message:"في الإنتاج يتم إرسال رابط آمن إلى البريد. هذه النسخة التجريبية لا ترسل رسائل فعلية."}));
app.post("/api/orders",async(req,res)=>{
 const {name,phone,address,items}=req.body;if(!name||!phone||!address||!Array.isArray(items)||!items.length)return res.status(400).json({error:"بيانات الطلب غير مكتملة"});
 const ids=items.map(x=>Number(x.id)).filter(Boolean);const rows=db.prepare(`SELECT * FROM products WHERE active=1 AND id IN (${ids.map(()=>"?").join(",")})`).all(...ids);
 const map=new Map(rows.map(x=>[x.id,x]));let subtotal=0, clean=[];
 for(const i of items){const p=map.get(Number(i.id)),q=Math.max(1,Math.min(99,Number(i.qty)||1));if(!p)return res.status(400).json({error:"منتج غير متاح"});subtotal+=p.price*q;clean.push({p,q})}
 const delivery=subtotal>=10?0:1.0,total=subtotal+delivery;
 const orderNo="ANB-"+new Date().getFullYear()+"-"+crypto.randomInt(100000,999999);
 const tx=db.transaction(()=>{const o=db.prepare("INSERT INTO orders(order_no,user_id,name,phone,address,payment,subtotal,delivery,total) VALUES(?,?,?,?,?,?,?,?,?)").run(orderNo,req.session.user?.id||null,name,phone,address,"cod",subtotal,delivery,total);const ins=db.prepare("INSERT INTO order_items(order_id,product_id,name,price,qty) VALUES(?,?,?,?,?)");clean.forEach(x=>ins.run(o.lastInsertRowid,x.p.id,x.p.name,x.p.price,x.q));return o.lastInsertRowid});
 const id=tx();res.json({orderNo,id,total,delivery,payment:"الدفع عند الاستلام"});
});
app.get("/api/my-orders",auth,(req,res)=>res.json(db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id)));
app.get("/api/admin/stats",admin,(req,res)=>res.json({
 orders:db.prepare("SELECT COUNT(*) c FROM orders").get().c,
 pending:db.prepare("SELECT COUNT(*) c FROM orders WHERE status IN ('new','preparing')").get().c,
 revenue:db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE status!='cancelled'").get().s,
 products:db.prepare("SELECT COUNT(*) c FROM products WHERE active=1").get().c
}));
app.get("/api/admin/orders",admin,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC").all()));
app.get("/api/admin/products",admin,(req,res)=>res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all()));
app.post("/api/admin/products",admin,(req,res)=>{const {name,description,price,image,category}=req.body;if(!name||!price)return res.status(400).json({error:"اسم وسعر المنتج مطلوبان"});const r=db.prepare("INSERT INTO products(name,description,price,image,category) VALUES(?,?,?,?,?)").run(name,description||"",Number(price),image||"",category||"main");res.json({id:r.lastInsertRowid})});
app.put("/api/admin/products/:id",admin,(req,res)=>{const {name,description,price,image,category,active}=req.body;db.prepare("UPDATE products SET name=?,description=?,price=?,image=?,category=?,active=? WHERE id=?").run(name,description,Number(price),image,category,active?1:0,req.params.id);res.json({ok:true})});
app.delete("/api/admin/products/:id",admin,(req,res)=>{db.prepare("UPDATE products SET active=0 WHERE id=?").run(req.params.id);res.json({ok:true})});
app.patch("/api/admin/orders/:id",admin,(req,res)=>{const allowed=["new","preparing","out_for_delivery","delivered","cancelled"];if(!allowed.includes(req.body.status))return res.status(400).json({error:"حالة غير صحيحة"});db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true})});
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.listen(PORT,()=>console.log(`عنبر يعمل على http://localhost:${PORT}`));