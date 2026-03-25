const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'apvs-crm-2024-xK9mP';
const EVO_BASE = 'https://painelsana-evolution-api.mofsig.easypanel.host';

// ── Database ───────────────────────────────────────────────────────────────────
const { mkdirSync } = require('fs');
mkdirSync('./data', { recursive: true });
const db = new DatabaseSync(process.env.DB_PATH || './data/crm.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'manager',
    name TEXT,
    consultant_id INTEGER,
    evo_instance TEXT,
    evo_key TEXT,
    evo_phone TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS consultants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    order_index INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    whatsapp TEXT
  );
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    plate TEXT,
    consultant_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'cotacao',
    notes TEXT,
    raw_data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS distribution_state (
    id INTEGER PRIMARY KEY DEFAULT 1,
    last_index INTEGER NOT NULL DEFAULT -1
  );
  CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Seed ───────────────────────────────────────────────────────────────────────
if (db.prepare('SELECT COUNT(*) as c FROM consultants').get().c === 0) {
  const ins = db.prepare('INSERT INTO consultants (name, order_index) VALUES (?, ?)');
  ['Fabiano','Bruno','Ana','Grazi','Stephanie'].forEach((n,i) => ins.run(n, i));
}
if (!db.prepare('SELECT id FROM distribution_state WHERE id = 1').get()) {
  db.prepare('INSERT INTO distribution_state (id, last_index) VALUES (1, -1)').run();
}
if (!db.prepare("SELECT id FROM users WHERE username = 'admin'").get()) {
  db.prepare('INSERT INTO users (username, password_hash, role, name) VALUES (?, ?, ?, ?)')
    .run('admin', bcrypt.hashSync('admin123', 10), 'admin', 'Administrador');
  console.log('✅ Admin criado: admin / admin123');
}
if (!db.prepare("SELECT id FROM users WHERE username = 'gerente'").get()) {
  db.prepare('INSERT INTO users (username, password_hash, role, name) VALUES (?, ?, ?, ?)')
    .run('gerente', bcrypt.hashSync('gerente123', 10), 'manager', 'Gerente');
  console.log('✅ Gerente criado: gerente / gerente123');
}

// ── Security headers ───────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ── Rate limiting (in-memory) ──────────────────────────────────────────────────
const _rl = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const key = `${ip}:${req.path}`;
    const now = Date.now();
    const hits = (_rl.get(key) || []).filter(t => now - t < windowMs);
    hits.push(now);
    _rl.set(key, hits);
    if (hits.length > max) return res.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
    next();
  };
}
// Clean rate store every 10 minutes
setInterval(() => { const now = Date.now(); _rl.forEach((v,k) => { if (!v.some(t => now-t < 600000)) _rl.delete(k); }); }, 600000);

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Não autorizado' });
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    next();
  } catch(e) {
    const msg = e.name === 'TokenExpiredError' ? 'Sessão expirada' : 'Token inválido';
    res.status(401).json({ error: msg });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso restrito' });
  next();
}

function canSeeLead(userRole, userConsultantId, leadConsultantId) {
  if (userRole === 'admin' || userRole === 'manager') return true;
  return userConsultantId === leadConsultantId;
}

// ── Auth ───────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', rateLimit(10, 60000), (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Preencha usuário e senha' });
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u || !bcrypt.compareSync(password, u.password_hash))
    return res.status(401).json({ error: 'Usuário ou senha incorretos' });
  const token = jwt.sign(
    { id: u.id, username: u.username, role: u.role, name: u.name, consultant_id: u.consultant_id || null },
    JWT_SECRET, { expiresIn: '12h' }
  );
  res.json({ token, user: { id: u.id, username: u.username, role: u.role, name: u.name, consultant_id: u.consultant_id || null } });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Preencha todos os campos' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Senha deve ter ao menos 6 caracteres' });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!u || !bcrypt.compareSync(currentPassword, u.password_hash))
    return res.status(401).json({ error: 'Senha atual incorreta' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res.json({ success: true });
});

// ── Webhook ────────────────────────────────────────────────────────────────────
app.post('/webhook', rateLimit(60, 60000), async (req, res) => {
  try {
    // Verificar chave secreta se configurada
    const secret = process.env.WEBHOOK_SECRET;
    if (secret) {
      const provided = req.headers['x-webhook-secret'] || req.query.secret;
      if (provided !== secret) return res.status(401).json({ error: 'Chave de webhook inválida' });
    }
    const d = req.body;
    const name  = (d.name  || d.nome  || d.Name  || d.NOME  || '').trim();
    const phone = (d.phone || d.telefone || d.whatsapp || d.Phone || d.celular || '').toString().replace(/\D/g,'');
    const plate = (d.plate || d.placa || d.Plate || d.PLACA || '').trim().toUpperCase();

    if (!name || !phone) return res.status(400).json({ error: 'Nome e telefone são obrigatórios' });

    // Dedup
    const existing = db.prepare(
      'SELECT l.*, c.name as consultant_name FROM leads l JOIN consultants c ON l.consultant_id=c.id WHERE l.name=? AND l.phone=?'
    ).get(name, phone);
    if (existing) {
      db.prepare('INSERT INTO activity_log (lead_id, action, detail) VALUES (?,?,?)').run(existing.id, 'duplicate_blocked', `Duplicata bloqueada — consultor: ${existing.consultant_name}`);
      return res.json({ status: 'duplicate', message: `Lead já existe. Consultor: ${existing.consultant_name}`, lead_id: existing.id });
    }

    // Round-robin
    const state = db.prepare('SELECT last_index FROM distribution_state WHERE id=1').get();
    const consultants = db.prepare('SELECT * FROM consultants WHERE active=1 ORDER BY order_index').all();
    if (!consultants.length) return res.status(500).json({ error: 'Nenhum consultor cadastrado' });
    const nextIdx = (state.last_index + 1) % consultants.length;
    const consultant = consultants[nextIdx];
    db.prepare('UPDATE distribution_state SET last_index=? WHERE id=1').run(nextIdx);

    const result = db.prepare(
      'INSERT INTO leads (name, phone, plate, consultant_id, status, raw_data) VALUES (?,?,?,?,?,?)'
    ).run(name, phone, plate, consultant.id, 'cotacao', JSON.stringify(d));
    const leadId = result.lastInsertRowid;
    db.prepare('INSERT INTO activity_log (lead_id, action, detail) VALUES (?,?,?)').run(leadId, 'created', `Distribuído para ${consultant.name}`);

    // Evo config (any manager with config)
    const evo = db.prepare("SELECT evo_instance, evo_key FROM users WHERE evo_instance IS NOT NULL AND evo_instance != '' AND evo_key IS NOT NULL AND evo_key != '' LIMIT 1").get();
    const now = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

    // Notifica consultor
    if (evo && consultant.whatsapp) {
      axios.post(`${EVO_BASE}/message/sendText/${evo.evo_instance}`,
        { number: consultant.whatsapp, text: `🚗 *Novo Lead para você!*\n\n👤 *Nome:* ${name}\n📱 *WhatsApp:* ${phone}\n🔢 *Placa:* ${plate||'Não informada'}\n📅 ${now}\n\n_Entre em contato o quanto antes!_` },
        { headers: { apikey: evo.evo_key }, timeout: 8000 }
      ).catch(e => console.error('Evo consultor:', e.message));
    }

    // Notifica gerentes e admins com evo configurado
    const managers = db.prepare("SELECT * FROM users WHERE role IN ('manager','admin') AND evo_instance IS NOT NULL AND evo_instance!='' AND evo_key IS NOT NULL AND evo_key!='' AND evo_phone IS NOT NULL AND evo_phone!=''").all();
    for (const m of managers) {
      axios.post(`${EVO_BASE}/message/sendText/${m.evo_instance}`,
        { number: m.evo_phone, text: `🚗 *Novo Lead!*\n\n👤 *Nome:* ${name}\n📱 *WhatsApp:* ${phone}\n🔢 *Placa:* ${plate||'Não informada'}\n👨‍💼 *Consultor:* ${consultant.name}\n📅 ${now}` },
        { headers: { apikey: m.evo_key }, timeout: 8000 }
      ).catch(e => console.error('Evo manager:', e.message));
    }

    res.json({ status: 'success', message: `Lead distribuído para ${consultant.name}`, lead_id: leadId, consultant: consultant.name });
  } catch (e) {
    console.error('Webhook error:', e);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// ── Leads ──────────────────────────────────────────────────────────────────────
app.get('/api/leads', auth, (req, res) => {
  const { consultant_id, status, search } = req.query;
  let q = 'SELECT l.*, c.name as consultant_name FROM leads l JOIN consultants c ON l.consultant_id=c.id WHERE 1=1';
  const p = [];
  if (req.user.role === 'consultor') { q += ' AND l.consultant_id=?'; p.push(req.user.consultant_id); }
  else if (consultant_id)            { q += ' AND l.consultant_id=?'; p.push(consultant_id); }
  if (status) { q += ' AND l.status=?'; p.push(status); }
  if (search) { q += ' AND (l.name LIKE ? OR l.phone LIKE ? OR l.plate LIKE ?)'; const s=`%${search}%`; p.push(s,s,s); }
  q += ' ORDER BY l.created_at DESC';
  res.json(db.prepare(q).all(...p));
});

app.get('/api/leads/:id', auth, (req, res) => {
  const lead = db.prepare('SELECT l.*, c.name as consultant_name FROM leads l JOIN consultants c ON l.consultant_id=c.id WHERE l.id=?').get(req.params.id);
  if (!lead) return res.status(404).json({ error: 'Lead não encontrado' });
  if (!canSeeLead(req.user.role, req.user.consultant_id, lead.consultant_id))
    return res.status(403).json({ error: 'Acesso negado' });
  const log = db.prepare('SELECT * FROM activity_log WHERE lead_id=? ORDER BY created_at DESC').all(req.params.id);
  res.json({ ...lead, activity: log });
});

app.patch('/api/leads/:id', auth, (req, res) => {
  const lead = db.prepare('SELECT * FROM leads WHERE id=?').get(req.params.id);
  if (!lead) return res.status(404).json({ error: 'Lead não encontrado' });
  if (!canSeeLead(req.user.role, req.user.consultant_id, lead.consultant_id))
    return res.status(403).json({ error: 'Acesso negado' });

  const { status, notes, consultant_id } = req.body;
  const valid = ['cotacao','negociacao','fechado'];
  const updates = ['updated_at = CURRENT_TIMESTAMP'];
  const p = [];
  if (status) {
    if (!valid.includes(status)) return res.status(400).json({ error: 'Status inválido' });
    updates.push('status=?'); p.push(status);
    db.prepare('INSERT INTO activity_log (lead_id,action,detail) VALUES (?,?,?)').run(req.params.id,'status_changed',`Status → ${status}`);
  }
  if (notes !== undefined) { updates.push('notes=?'); p.push(notes); }
  if (consultant_id && req.user.role !== 'consultor') {
    updates.push('consultant_id=?'); p.push(consultant_id);
    const c = db.prepare('SELECT name FROM consultants WHERE id=?').get(consultant_id);
    db.prepare('INSERT INTO activity_log (lead_id,action,detail) VALUES (?,?,?)').run(req.params.id,'reassigned',`Reatribuído → ${c?.name}`);
  }
  p.push(req.params.id);
  db.prepare(`UPDATE leads SET ${updates.join(', ')} WHERE id=?`).run(...p);
  res.json(db.prepare('SELECT l.*, c.name as consultant_name FROM leads l JOIN consultants c ON l.consultant_id=c.id WHERE l.id=?').get(req.params.id));
});

app.delete('/api/leads/:id', auth, adminOnly, (req, res) => {
  db.prepare('DELETE FROM activity_log WHERE lead_id=?').run(req.params.id);
  db.prepare('DELETE FROM leads WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Stats ──────────────────────────────────────────────────────────────────────
app.get('/api/stats', auth, (req, res) => {
  const isConsultor = req.user.role === 'consultor';
  const cid = req.user.consultant_id;

  let total, byStatus, byConsultant, recent;
  if (isConsultor) {
    total = db.prepare('SELECT COUNT(*) as c FROM leads WHERE consultant_id=?').get(cid).c;
    byStatus = db.prepare('SELECT status, COUNT(*) as count FROM leads WHERE consultant_id=? GROUP BY status').all(cid);
    byConsultant = db.prepare(`
      SELECT c.id, c.name, c.order_index,
        COUNT(l.id) as total,
        SUM(CASE WHEN l.status='cotacao' THEN 1 ELSE 0 END) as cotacao,
        SUM(CASE WHEN l.status='negociacao' THEN 1 ELSE 0 END) as negociacao,
        SUM(CASE WHEN l.status='fechado' THEN 1 ELSE 0 END) as fechado
      FROM consultants c LEFT JOIN leads l ON c.id=l.consultant_id AND l.consultant_id=?
      WHERE c.id=? GROUP BY c.id
    `).all(cid, cid);
    recent = db.prepare('SELECT l.*, c.name as consultant_name FROM leads l JOIN consultants c ON l.consultant_id=c.id WHERE l.consultant_id=? ORDER BY l.created_at DESC LIMIT 10').all(cid);
  } else {
    total = db.prepare('SELECT COUNT(*) as c FROM leads').get().c;
    byStatus = db.prepare('SELECT status, COUNT(*) as count FROM leads GROUP BY status').all();
    byConsultant = db.prepare(`
      SELECT c.id, c.name, c.order_index,
        COUNT(l.id) as total,
        SUM(CASE WHEN l.status='cotacao' THEN 1 ELSE 0 END) as cotacao,
        SUM(CASE WHEN l.status='negociacao' THEN 1 ELSE 0 END) as negociacao,
        SUM(CASE WHEN l.status='fechado' THEN 1 ELSE 0 END) as fechado
      FROM consultants c LEFT JOIN leads l ON c.id=l.consultant_id
      WHERE c.active=1 GROUP BY c.id ORDER BY c.order_index
    `).all();
    recent = db.prepare('SELECT l.*, c.name as consultant_name FROM leads l JOIN consultants c ON l.consultant_id=c.id ORDER BY l.created_at DESC LIMIT 10').all();
  }
  res.json({ total, byStatus, byConsultant, recent });
});

// ── Consultants ────────────────────────────────────────────────────────────────
app.get('/api/consultants', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM consultants ORDER BY order_index').all());
});
app.put('/api/consultants/:id', auth, adminOnly, (req, res) => {
  const phone = (req.body.whatsapp || '').toString().replace(/\D/g,'') || null;
  const name  = (req.body.name || '').trim();
  if (name) db.prepare('UPDATE consultants SET name=?, whatsapp=? WHERE id=?').run(name, phone, req.params.id);
  else       db.prepare('UPDATE consultants SET whatsapp=? WHERE id=?').run(phone, req.params.id);
  res.json({ success: true });
});

// ── Users (admin) ──────────────────────────────────────────────────────────────
app.get('/api/users', auth, adminOnly, (req, res) => {
  res.json(db.prepare(`
    SELECT u.id, u.username, u.role, u.name, u.consultant_id, c.name as consultant_name,
           u.evo_instance, u.evo_phone, u.created_at,
           CASE WHEN u.evo_key IS NOT NULL AND u.evo_key != '' THEN 1 ELSE 0 END as has_evo_key
    FROM users u LEFT JOIN consultants c ON u.consultant_id=c.id
    WHERE u.role != 'admin'
  `).all());
});

app.post('/api/users', auth, adminOnly, (req, res) => {
  const { username, password, role, name, consultant_id, evo_instance, evo_key, evo_phone } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
  if (role === 'consultor' && !consultant_id) return res.status(400).json({ error: 'Selecione o consultor vinculado' });
  try {
    const r = db.prepare('INSERT INTO users (username,password_hash,role,name,consultant_id,evo_instance,evo_key,evo_phone) VALUES (?,?,?,?,?,?,?,?)')
      .run(username, bcrypt.hashSync(password,10), role||'manager', name||username, consultant_id||null, evo_instance||null, evo_key||null, evo_phone||null);
    res.status(201).json({ id: r.lastInsertRowid, username, role: role||'manager', name });
  } catch { res.status(400).json({ error: 'Usuário já existe' }); }
});

app.put('/api/users/:id', auth, adminOnly, (req, res) => {
  const { name, username, password, role, consultant_id, evo_instance, evo_key, evo_phone } = req.body;
  const updates = []; const p = [];
  if (name)                          { updates.push('name=?');          p.push(name); }
  if (username)                      { updates.push('username=?');      p.push(username); }
  if (role)                          { updates.push('role=?');          p.push(role); }
  if (consultant_id !== undefined)   { updates.push('consultant_id=?'); p.push(consultant_id||null); }
  if (evo_instance !== undefined)    { updates.push('evo_instance=?');  p.push(evo_instance||null); }
  if (evo_key)                       { updates.push('evo_key=?');       p.push(evo_key); }
  if (evo_phone !== undefined)       { updates.push('evo_phone=?');     p.push(evo_phone||null); }
  if (password)                      { updates.push('password_hash=?'); p.push(bcrypt.hashSync(password,10)); }
  if (!updates.length) return res.status(400).json({ error: 'Nada para atualizar' });
  p.push(req.params.id);
  db.prepare(`UPDATE users SET ${updates.join(',')} WHERE id=?`).run(...p);
  res.json({ success: true });
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Não pode deletar a si mesmo' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ── Analytics ──────────────────────────────────────────────────────────────────
app.get('/api/analytics', auth, (req, res) => {
  const { from, to } = req.query;
  const isConsultor = req.user.role === 'consultor';
  const cid = req.user.consultant_id;

  const dp = [];
  let dj = '';
  if (from) { dj += ' AND l.created_at >= ?'; dp.push(from); }
  if (to)   { dj += ' AND l.created_at <= ?'; dp.push(to + ' 23:59:59'); }

  let wh = 'WHERE 1=1' + dj;
  const wp = [...dp];
  if (isConsultor) { wh += ' AND l.consultant_id=?'; wp.push(cid); }

  const total    = db.prepare(`SELECT COUNT(*) as c FROM leads l ${wh}`).get(...wp).c;
  const byStatus = db.prepare(`SELECT status, COUNT(*) as count FROM leads l ${wh} GROUP BY status`).all(...wp);

  const rankWhere = isConsultor ? 'WHERE c.id=?' : 'WHERE c.active=1';
  const rankParams = [...dp, ...(isConsultor ? [cid] : [])];
  const ranking = db.prepare(`
    SELECT c.name, c.order_index,
      COUNT(l.id) as total,
      SUM(CASE WHEN l.status='fechado'    THEN 1 ELSE 0 END) as fechados,
      SUM(CASE WHEN l.status='negociacao' THEN 1 ELSE 0 END) as negociacao,
      SUM(CASE WHEN l.status='cotacao'    THEN 1 ELSE 0 END) as cotacao
    FROM consultants c
    LEFT JOIN leads l ON c.id=l.consultant_id${dj}
    ${rankWhere}
    GROUP BY c.id ORDER BY fechados DESC, total DESC
  `).all(...rankParams);

  res.json({ total, byStatus, ranking });
});

app.post('/api/analytics/whatsapp', auth, async (req, res) => {
  const { from, to, phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Número obrigatório' });

  const dp = [];
  let dj = '';
  if (from) { dj += ' AND l.created_at >= ?'; dp.push(from); }
  if (to)   { dj += ' AND l.created_at <= ?'; dp.push(to + ' 23:59:59'); }
  const wh = 'WHERE 1=1' + dj;

  const total    = db.prepare(`SELECT COUNT(*) as c FROM leads l ${wh}`).get(...dp).c;
  const byStatus = db.prepare(`SELECT status, COUNT(*) as count FROM leads l ${wh} GROUP BY status`).all(...dp);
  const ranking  = db.prepare(`
    SELECT c.name,
      COUNT(l.id) as total,
      SUM(CASE WHEN l.status='fechado'    THEN 1 ELSE 0 END) as fechados,
      SUM(CASE WHEN l.status='negociacao' THEN 1 ELSE 0 END) as negociacao,
      SUM(CASE WHEN l.status='cotacao'    THEN 1 ELSE 0 END) as cotacao
    FROM consultants c LEFT JOIN leads l ON c.id=l.consultant_id${dj}
    WHERE c.active=1 GROUP BY c.id ORDER BY fechados DESC, total DESC
  `).all(...dp);

  const s = Object.fromEntries(byStatus.map(x => [x.status, x.count]));
  const medals = ['🥇','🥈','🥉'];
  const periodo = from && to ? `${from} até ${to}` : from ? `a partir de ${from}` : to ? `até ${to}` : 'todo o período';
  const rankLines = ranking.map((c,i) => `${medals[i]||`${i+1}º`} *${c.name}* — ${c.fechados||0} fechados | ${c.negociacao||0} negoc. | ${c.cotacao||0} cotação`).join('\n');

  const text = `📊 *Relatório de Performance — APVS Central Minas*\n📅 Período: ${periodo}\n🗓 Gerado em: ${new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })}\n\n━━━━━━━━━━━━━━━\n📥 *Total de leads:* ${total}\n🔵 Em Cotação: ${s.cotacao||0}\n🟡 Em Negociação: ${s.negociacao||0}\n🟢 Fechados: ${s.fechado||0}\n━━━━━━━━━━━━━━━\n\n🏆 *Ranking de Fechamentos*\n${rankLines}`;

  const evo = db.prepare("SELECT evo_instance, evo_key FROM users WHERE evo_instance IS NOT NULL AND evo_instance!='' AND evo_key IS NOT NULL AND evo_key!='' LIMIT 1").get();
  if (!evo) return res.status(503).json({ error: 'Nenhuma instância Evolution API configurada' });

  try {
    await axios.post(`${EVO_BASE}/message/sendText/${evo.evo_instance}`,
      { number: phone.replace(/\D/g,''), text },
      { headers: { apikey: evo.evo_key }, timeout: 10000 }
    );
    res.json({ success: true });
  } catch(e) {
    res.status(502).json({ error: 'Falha ao enviar via WhatsApp: ' + (e.response?.data?.message || e.message) });
  }
});

// ── Activity ───────────────────────────────────────────────────────────────────
app.get('/api/activity', auth, (req, res) => {
  if (req.user.role === 'consultor') {
    res.json(db.prepare(`
      SELECT a.*, l.name as lead_name FROM activity_log a
      LEFT JOIN leads l ON a.lead_id=l.id
      WHERE l.consultant_id=? ORDER BY a.created_at DESC LIMIT 50
    `).all(req.user.consultant_id));
  } else {
    res.json(db.prepare(`
      SELECT a.*, l.name as lead_name FROM activity_log a
      LEFT JOIN leads l ON a.lead_id=l.id
      ORDER BY a.created_at DESC LIMIT 50
    `).all());
  }
});

// ── Pages ──────────────────────────────────────────────────────────────────────
app.get('/', (_, res) => res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/dashboard', (_, res) => res.sendFile(path.join(__dirname,'public','dashboard.html')));

app.listen(PORT, () => {
  console.log(`\n🚗 CRM APVS rodando na porta ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`🔗 Webhook: http://localhost:${PORT}/webhook\n`);
});
