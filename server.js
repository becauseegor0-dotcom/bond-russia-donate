require('dotenv').config();
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL?.includes('render.com') || process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined });
const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET || !process.env.ADMIN_PASSWORD_HASH) {
  console.error('Required env vars: DATABASE_URL, SESSION_SECRET, ADMIN_PASSWORD_HASH');
  process.exit(1);
}
const PRICE_PER_RUB = 0.5;
const STATUSES = ['Ожидает', 'Оплачено', 'Выдано', 'Отклонено'];

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'] } } }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'bond_admin_session', secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false });
const createLimit = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY, nickname TEXT NOT NULL, server_name TEXT NOT NULL,
    rubles INTEGER NOT NULL, bond_rub INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'Ожидает',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY, bond_rub INTEGER NOT NULL UNIQUE, rubles INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
  )`);
  const defaults = [[100,50],[500,250],[1000,500],[5000,2500],[10000,5000]];
  for (const [bond, rub] of defaults) await pool.query('INSERT INTO packages (bond_rub, rubles) VALUES ($1,$2) ON CONFLICT (bond_rub) DO NOTHING', [bond,rub]);
}
function adminOnly(req,res,next){ if(req.session?.admin) return next(); return res.status(401).json({error:'Требуется вход администратора'}); }
function cleanText(v,max){ return String(v || '').trim().replace(/[<>]/g,'').slice(0,max); }

app.get('/api/packages', async (_req,res) => {
  try { const q=await pool.query('SELECT bond_rub, rubles FROM packages WHERE active=TRUE ORDER BY bond_rub'); res.json(q.rows); }
  catch(e){ console.error(e); res.status(500).json({error:'Не удалось загрузить пакеты'}); }
});
app.post('/api/requests', createLimit, async (req,res) => {
  try {
    const nickname=cleanText(req.body.nickname,32), server=cleanText(req.body.server,40);
    const rubles=Number(req.body.rubles);
    if(!/^[\p{L}\p{N}_ .-]{2,32}$/u.test(nickname)) return res.status(400).json({error:'Проверь никнейм (2–32 символа)'});
    if(!server || server.length>40) return res.status(400).json({error:'Укажи сервер'});
    if(!Number.isInteger(rubles) || rubles<50 || rubles>100000) return res.status(400).json({error:'Сумма должна быть целым числом от 50 до 100 000 ₽'});
    const bond=rubles*2;
    const id=crypto.randomBytes(9).toString('base64url').toUpperCase();
    await pool.query('INSERT INTO requests (id,nickname,server_name,rubles,bond_rub) VALUES ($1,$2,$3,$4,$5)',[id,nickname,server,rubles,bond]);
    res.status(201).json({id,nickname,server,rubles,bond_rub:bond,status:'Ожидает'});
  } catch(e){ console.error(e); res.status(500).json({error:'Не удалось создать заявку'}); }
});
app.get('/api/requests/:id', async (req,res) => {
  try { const id=cleanText(req.params.id,32); const q=await pool.query('SELECT id,nickname,server_name,rubles,bond_rub,status,created_at FROM requests WHERE id=$1',[id]); if(!q.rowCount) return res.status(404).json({error:'Заявка не найдена'}); res.json(q.rows[0]); }
  catch(e){ console.error(e); res.status(500).json({error:'Ошибка поиска'}); }
});
app.post('/api/admin/login',loginLimit,async(req,res)=>{
  const password=String(req.body.password||'');
  const hash=process.env.ADMIN_PASSWORD_HASH;
  if(!hash || !(await bcrypt.compare(password,hash))) return res.status(401).json({error:'Неверный пароль'});
  req.session.admin=true; res.json({ok:true});
});
app.post('/api/admin/logout',adminOnly,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/me',(req,res)=>res.json({admin:!!req.session?.admin}));
app.get('/api/admin/requests',adminOnly,async(req,res)=>{
  try { const search=cleanText(req.query.search,50); const q=await pool.query(`SELECT id,nickname,server_name,rubles,bond_rub,status,created_at,updated_at FROM requests WHERE ($1='' OR nickname ILIKE $2 OR id ILIKE $2) ORDER BY created_at DESC LIMIT 500`,[search,`%${search}%`]); res.json(q.rows); }
  catch(e){console.error(e);res.status(500).json({error:'Ошибка загрузки заявок'});}
});
app.patch('/api/admin/requests/:id',adminOnly,async(req,res)=>{
  try { const status=String(req.body.status||''); const bond=Number(req.body.bond_rub); if(!STATUSES.includes(status)) return res.status(400).json({error:'Недопустимый статус'}); if(!Number.isInteger(bond)||bond<0||bond>200000) return res.status(400).json({error:'Некорректное количество BOND RUB'}); const q=await pool.query('UPDATE requests SET status=$1,bond_rub=$2,updated_at=NOW() WHERE id=$3 RETURNING id,status,bond_rub',[status,bond,cleanText(req.params.id,32)]); if(!q.rowCount) return res.status(404).json({error:'Заявка не найдена'}); res.json(q.rows[0]); }
  catch(e){console.error(e);res.status(500).json({error:'Не удалось обновить заявку'});}
});
app.put('/api/admin/packages',adminOnly,async(req,res)=>{
  try { const items=req.body.packages; if(!Array.isArray(items)||items.length>20) return res.status(400).json({error:'Некорректный список пакетов'}); for(const p of items){const bond=Number(p.bond_rub),rub=Number(p.rubles);if(!Number.isInteger(bond)||bond<1||bond>200000||!Number.isInteger(rub)||rub<1||rub>100000) return res.status(400).json({error:'Проверь цены и количество'}); await pool.query('INSERT INTO packages (bond_rub,rubles,active) VALUES ($1,$2,TRUE) ON CONFLICT (bond_rub) DO UPDATE SET rubles=EXCLUDED.rubles,active=TRUE',[bond,rub]);} res.json({ok:true}); }
  catch(e){console.error(e);res.status(500).json({error:'Не удалось сохранить пакеты'});}
});
app.get('/health',(_req,res)=>res.json({ok:true,service:'BOND RUSSIA DONATE'}));
app.get('*',(req,res)=>{ if(req.path.startsWith('/api/')) return res.status(404).json({error:'Not found'}); res.sendFile(path.join(__dirname,'public','index.html')); });

initDb().then(()=>app.listen(PORT,()=>console.log(`BOND RUSSIA DONATE listening on ${PORT}`))).catch(e=>{console.error('Database initialization failed',e);process.exit(1);});
