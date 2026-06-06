/**
 * SABER RURAL — index.js
 */

const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const multer   = require('multer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Directorios de datos ──────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

[DATA_DIR, UPLOADS_DIR].forEach(d => { 
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); 
});

// Se usa la extensión .store (no .json) para que el recargador automático de
// Bonto/nodemon NO reinicie el servidor cada vez que se guardan datos.
// El contenido sigue siendo JSON por dentro.
const DB_FILE   = path.join(DATA_DIR, 'usuarios.store');
const CHAT_FILE = path.join(DATA_DIR, 'chat.store');
const ACT_FILE  = path.join(DATA_DIR, 'actividad.store');

// ── Helpers de persistencia ───────────────────────────────────
function readJSON(file, def = {}) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function hashPass(p) {
  let h = 0x811c9dc5;
  for (let i = 0; i < p.length; i++) { h ^= p.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return 'h' + h.toString(16).padStart(8, '0');
}
function genToken() { return crypto.randomBytes(24).toString('hex'); }

// ── Base de datos en memoria (cargada desde disco) ────────────
let db = readJSON(DB_FILE, { users: {}, tokens: {}, students: {}, notas: [], recursos: [], actividad: [], registros: [], resultados: [] });
if (!Array.isArray(db.registros))  db.registros  = [];
if (!Array.isArray(db.resultados)) db.resultados = [];
if (!db.config) db.config = {};
if (!db.config.codigoInscripcion) {
  db.config.codigoInscripcion = process.env.CODIGO_INSCRIPCION || 'INEPUN-2026';
}

if (!db.users['admin']) {
  db.users['admin'] = {
    username: 'admin', passHash: hashPass('admin123'),
    name: 'Docente INEPUN', emoji: '👨‍🏫', role: 'tutor',
    institucion: 'I.E. Pueblo Nuevo', primerIngreso: false
  };
  writeJSON(DB_FILE, db);
  console.log('[INIT] Usuario admin creado con clave admin123');
}

// ── Presencia online ──────────────────────────────────────────
const onlineUsers = new Map();
const PRESENCIA_TTL = 60 * 1000;

function limpiarPresenciaVencida() {
  const ahora = Date.now();
  for (const [u, d] of onlineUsers.entries()) {
    if (ahora - new Date(d.ts).getTime() > PRESENCIA_TTL) onlineUsers.delete(u);
  }
}
setInterval(limpiarPresenciaVencida, 30000);

// ── Middleware ────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Servir la raíz como estática para mapear HTML, CSS y JS locales en Bonto
app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));

// ── Auth middleware ───────────────────────────────────────────
function authRequired(req, res, next) {
  const hdr = req.headers['authorization'] || '';
  const tok = hdr.replace('Bearer ', '').trim();
  if (!tok || !db.tokens[tok]) return res.status(401).json({ error: 'Sesión no válida' });
  req.username = db.tokens[tok];
  req.user     = db.users[req.username];
  if (req.user) {
    onlineUsers.set(req.username, {
      username: req.username, name: req.user.name,
      emoji: req.user.emoji, role: req.user.role,
      ts: new Date().toISOString()
    });
  }
  next();
}

// ── PING ─────────────────────────────────────────────────────
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, ts: Date.now(), msg: 'SABER RURAL online' });
});

// ── LOGIN ─────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password, institucion } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });

  const u = db.users[username.toLowerCase()];
  if (!u || u.passHash !== hashPass(password))
    return res.status(401).json({ error: 'Usuario o clave incorrectos' });

  if (institucion) { u.institucion = institucion; writeJSON(DB_FILE, db); }

  const token = genToken();
  db.tokens[token] = username.toLowerCase();
  writeJSON(DB_FILE, db);

  onlineUsers.set(username.toLowerCase(), {
    username: username.toLowerCase(), name: u.name,
    emoji: u.emoji, role: u.role,
    ts: new Date().toISOString()
  });

  res.json({
    token,
    user: {
      username: u.username, name: u.name, emoji: u.emoji,
      role: u.role, primerIngreso: u.primerIngreso || false,
      institucion: u.institucion || ''
    }
  });
});

// ── REGISTRO PÚBLICO (SOLO ESTUDIANTES) ───────────────────────
app.post('/api/register', (req, res) => {
  const { nombre, colegio, username, password, grado, codigo } = req.body || {};

  // 🔒 Blindaje: solo quien tenga el código del curso puede registrarse
  const codigoEnviado   = String(codigo || '').trim().toLowerCase();
  const codigoRequerido = String((db.config && db.config.codigoInscripcion) || '').trim().toLowerCase();
  if (!codigoRequerido || codigoEnviado !== codigoRequerido)
    return res.status(403).json({ error: 'Código de inscripción inválido. Pídeselo a tu docente.' });

  if (!nombre || !username || !password)
    return res.status(400).json({ error: 'Faltan datos: nombre, usuario y contraseña son obligatorios' });
  if (String(password).length < 6)
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

  const u = String(username).toLowerCase().replace(/\s+/g, '');
  if (u.length < 4)
    return res.status(400).json({ error: 'El usuario debe tener al menos 4 caracteres' });
  if (db.users[u])
    return res.status(409).json({ error: 'Ese nombre de usuario ya está en uso' });

  db.users[u] = {
    username: u, name: nombre, institucion: colegio || '', role: 'estudiante',
    passHash: hashPass(password), primerIngreso: false, emoji: '🧑‍🎓', grado: grado || '',
    createdAt: new Date().toISOString()
  };

  db.registros.push({ usuario: u, nombre, colegio: colegio || '', fecha: new Date().toISOString() });
  writeJSON(DB_FILE, db);
  res.json({ ok: true, message: 'Cuenta creada. Ya puedes iniciar sesión.' });
});

app.get('/api/presencia', authRequired, (req, res) => {
  limpiarPresenciaVencida();
  res.json({ online: Array.from(onlineUsers.values()) });
});

app.post('/api/presencia', authRequired, (req, res) => {
  const { username, name, emoji, role } = req.body || {};
  onlineUsers.set(req.username, {
    username: req.username,
    name:  name  || req.user?.name  || req.username,
    emoji: emoji || req.user?.emoji || '👤',
    role:  role  || req.user?.role  || 'estudiante',
    ts: new Date().toISOString()
  });
  res.json({ ok: true });
});

// ── CHAT ──────────────────────────────────────────────────────
app.get('/api/chat', authRequired, (req, res) => {
  const msgs = readJSON(CHAT_FILE, []);
  const desde = req.query.desde;
  const filtrado = desde ? msgs.filter(m => m.ts && m.ts > desde) : msgs.slice(-100);
  res.json({ msgs: filtrado });
});

app.post('/api/chat', authRequired, (req, res) => {
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Mensaje vacío' });
  const msgs = readJSON(CHAT_FILE, []);
  const u = db.users[req.username] || {};
  const msg = {
    user: req.username, name: u.name || req.username,
    emoji: u.emoji || '👤', role: u.role || 'estudiante',
    text: text.trim(), time: new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' }),
    type: 'msg', ts: new Date().toISOString()
  };
  msgs.push(msg);
  if (msgs.length > 300) msgs.splice(0, msgs.length - 300);
  writeJSON(CHAT_FILE, msgs);
  res.json({ ok: true, msg });
});

app.delete('/api/chat', authRequired, (req, res) => {
  const u = db.users[req.username];
  if (!u || u.role !== 'tutor') return res.status(403).json({ error: 'Solo el docente puede limpiar el chat' });
  writeJSON(CHAT_FILE, [{ type:'sys', text:'🗑️ Chat limpiado · ' + new Date().toLocaleString('es-CO'), ts: new Date().toISOString() }]);
  res.json({ ok: true });
});

// ── ESTUDIANTES ───────────────────────────────────────────────
app.get('/api/estudiantes', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });

  const ests = Object.values(db.users)
    .filter(u => u.role === 'estudiante')
    .map(u => ({
      username: u.username, name: u.name, emoji: u.emoji,
      grado: u.grado || '—', primerIngreso: u.primerIngreso || false,
      ultimaConexion: u.ultimaConexion || null,
      totalActividades: (db.actividad || []).filter(a => a.username === u.username).length,
      promedio: calcularPromedio(u.username)
    }));
  res.json({ estudiantes: ests });
});

function calcularPromedio(username) {
  const acts = (db.actividad || []).filter(a => a.username === username && a.pct != null);
  if (!acts.length) return 0;
  return Math.round(acts.reduce((s, a) => s + (a.pct || 0), 0) / acts.length);
}

app.post('/api/estudiantes', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });

  const { username, nombre, grado, clave } = req.body || {};
  if (!username || !nombre || !clave) return res.status(400).json({ error: 'Faltan campos' });
  const u = username.toLowerCase().replace(/\s+/g, '');
  if (db.users[u]) return res.status(409).json({ error: 'Usuario ya existe' });

  db.users[u] = {
    username: u, passHash: hashPass(clave),
    name: nombre, emoji: '👨‍🎓', role: 'estudiante',
    grado: grado || '11°', primerIngreso: true,
    creadoPor: req.username, creadoEn: new Date().toISOString()
  };
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

app.delete('/api/estudiantes/:username', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  const u = req.params.username;
  if (u === 'admin') return res.status(403).json({ error: 'No se puede eliminar al administrador' });
  if (!db.users[u]) return res.status(404).json({ error: 'No encontrado' });
  if (db.users[u].role === 'tutor') return res.status(400).json({ error: 'No se puede eliminar a un docente' });
  delete db.users[u];
  for (const t of Object.keys(db.tokens)) { if (db.tokens[t] === u) delete db.tokens[t]; }
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

// ── CREAR DOCENTE ─────────────────────────────────────────────
app.post('/api/docentes', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor')
    return res.status(403).json({ error: 'Solo el administrador puede crear docentes' });

  const { username, nombre, clave } = req.body || {};
  if (!username || !nombre || !clave) return res.status(400).json({ error: 'Faltan campos' });
  if (String(clave).length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  const u = String(username).toLowerCase().replace(/\s+/g, '');
  if (db.users[u]) return res.status(409).json({ error: 'Ese usuario ya existe' });

  db.users[u] = {
    username: u, passHash: hashPass(clave),
    name: nombre, emoji: '👩‍🏫', role: 'tutor',
    institucion: tutorU.institucion || '', primerIngreso: false,
    creadoPor: req.username, creadoEn: new Date().toISOString()
  };
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

app.get('/api/registros', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  res.json({ registros: (db.registros || []).slice().reverse() });
});

// ── CÓDIGO DE INSCRIPCIÓN (solo docentes) ─────────────────────
app.get('/api/codigo', authRequired, (req, res) => {
  const u = db.users[req.username];
  if (!u || u.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  res.json({ codigo: (db.config && db.config.codigoInscripcion) || '' });
});

app.post('/api/codigo', authRequired, (req, res) => {
  const u = db.users[req.username];
  if (!u || u.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  const nuevo = String((req.body || {}).codigo || '').trim();
  if (nuevo.length < 4) return res.status(400).json({ error: 'El código debe tener al menos 4 caracteres' });
  if (!db.config) db.config = {};
  db.config.codigoInscripcion = nuevo;
  writeJSON(DB_FILE, db);
  res.json({ ok: true, codigo: nuevo });
});

app.post('/api/estudiantes/:username/reset', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  const u = db.users[req.params.username];
  if (!u) return res.status(404).json({ error: 'No encontrado' });
  u.passHash = hashPass(req.body.nuevaClave || 'saber2026');
  u.primerIngreso = true;
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

app.post('/api/estudiantes/:username/reset-progreso', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  db.actividad  = (db.actividad  || []).filter(a => a.username !== req.params.username);
  db.resultados = (db.resultados || []).filter(r => r.username !== req.params.username);
  writeJSON(DB_FILE, db);
  writeJSON(ACT_FILE, db.actividad);
  res.json({ ok: true });
});

// ── CAMBIAR CONTRASEÑA ────────────────────────────────────────
app.post('/api/cambiar-password', authRequired, (req, res) => {
  const actual = req.body.actual ?? req.body.currentPassword;
  const nueva  = req.body.nueva  ?? req.body.newPassword;
  const u = db.users[req.username];
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (!nueva || nueva.length < 6) return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres' });
  if (u.passHash !== hashPass(actual)) return res.status(401).json({ error: 'Clave actual incorrecta' });
  u.passHash = hashPass(nueva);
  u.primerIngreso = false;
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

// ── CAMBIO OBLIGATORIO DE CREDENCIALES ────────────────────────
app.post('/api/cambiar-credenciales', authRequired, (req, res) => {
  const { nuevoUsername, nuevaClave } = req.body || {};
  const actualUsername = req.username;
  const u = db.users[actualUsername];
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (!nuevoUsername || !nuevaClave) return res.status(400).json({ error: 'Faltan datos' });

  const limpio = String(nuevoUsername).toLowerCase().replace(/\s+/g, '');
  if (limpio.length < 4)     return res.status(400).json({ error: 'El usuario debe tener al menos 4 caracteres' });
  if (nuevaClave.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

  const cambiaNombre = (limpio !== actualUsername);
  if (cambiaNombre && db.users[limpio]) return res.status(409).json({ error: 'Ese nombre de usuario ya está en uso' });

  u.passHash = hashPass(nuevaClave);
  u.primerIngreso = false;

  if (cambiaNombre) {
    u.username = limpio;
    db.users[limpio] = u;
    delete db.users[actualUsername];
    (db.actividad || []).forEach(a => { if (a.username === actualUsername) a.username = limpio; });
    for (const t of Object.keys(db.tokens)) { if (db.tokens[t] === actualUsername) delete db.tokens[t]; }
    onlineUsers.delete(actualUsername);
  }

  const nuevoToken = genToken();
  db.tokens[nuevoToken] = u.username;
  writeJSON(DB_FILE, db);
  writeJSON(ACT_FILE, db.actividad || []);

  onlineUsers.set(u.username, {
    username: u.username, name: u.name, emoji: u.emoji, role: u.role,
    ts: new Date().toISOString()
  });

  res.json({
    ok: true, token: nuevoToken,
    user: {
      username: u.username, name: u.name, emoji: u.emoji,
      role: u.role, institucion: u.institucion || '', primerIngreso: false
    }
  });
});

// ── ACTIVIDAD ─────────────────────────────────────────────────
app.post('/api/actividad', authRequired, (req, res) => {
  const { tipo, detalle, modulo, pct } = req.body || {};
  if (!db.actividad) db.actividad = [];
  db.actividad.push({
    username: req.username, tipo, detalle, modulo,
    pct: pct != null ? Number(pct) : null,
    ts: new Date().toISOString()
  });
  if (db.users[req.username]) db.users[req.username].ultimaConexion = new Date().toISOString();
  writeJSON(DB_FILE, db);
  writeJSON(ACT_FILE, db.actividad);
  res.json({ ok: true });
});

// ── NOTAS ─────────────────────────────────────────────────────
app.get('/api/notes', authRequired, (req, res) => {
  res.json({ notas: db.notas || [] });
});

app.post('/api/notas/sync', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  db.notas = req.body.notas || [];
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

// ── DASHBOARD ─────────────────────────────────────────────────
app.get('/api/dashboard', authRequired, (req, res) => {
  const actsAll = db.actividad || [];
  const usuarios = Object.values(db.users).filter(u => u.role === 'estudiante');
  const resumen = usuarios.map(u => {
    const acts = actsAll.filter(a => a.username === u.username);
    const quizzes = acts.filter(a => a.tipo === 'quiz');
    const promQ = quizzes.length
      ? Math.round(quizzes.reduce((s, q) => s + (q.pct || 0), 0) / quizzes.length)
      : null;
    return {
      username: u.username, name: u.name, emoji: u.emoji, grado: u.grado || '—',
      totalActividades: acts.length, quizzesHechos: quizzes.length,
      promedioQuiz: promQ != null ? promQ + '%' : 'Sin quizzes',
      ultimaConexion: u.ultimaConexion || null,
      enLinea: onlineUsers.has(u.username)
    };
  });
  res.json({ estudiantes: resumen, totalEnLinea: onlineUsers.size });
});

// ── PERFIL ────────────────────────────────────────────────────
app.get('/api/perfil/:username', authRequired, (req, res) => {
  const u = db.users[req.params.username];
  if (!u) return res.status(404).json({ error: 'No encontrado' });
  res.json({ perfil: {
    username: u.username, name: u.name, nombre: u.name, emoji: u.emoji, role: u.role,
    grado: u.grado, institucion: u.institucion,
    municipio: u.municipio || '', telefono: u.telefono || '',
    fechaNacimiento: u.fechaNacimiento || '', bio: u.bio || '',
    intereses: u.intereses || '', directorGrupo: u.directorGrupo || '',
    fotoUrl: u.fotoUrl || null
  }});
});

app.get('/api/perfiles', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  const perfiles = Object.values(db.users)
    .filter(u => u.role === 'estudiante')
    .map(u => ({
      username: u.username, name: u.name, nombre: u.name, emoji: u.emoji, role: u.role,
      grado: u.grado || '—', municipio: u.municipio || '', fotoUrl: u.fotoUrl || null,
      stats: { promedioQuiz: calcularPromedio(u.username) }
    }));
  res.json({ perfiles });
});

app.post('/api/perfil/:username', authRequired, (req, res) => {
  if (req.username !== req.params.username && db.users[req.username]?.role !== 'tutor')
    return res.status(403).json({ error: 'Sin permiso' });
  const u = db.users[req.params.username];
  if (!u) return res.status(404).json({ error: 'No encontrado' });
  const b = req.body || {};
  const nombre = b.name ?? b.nombre;
  if (nombre)                     u.name = nombre;
  if (b.emoji)                    u.emoji = b.emoji;
  if (b.grado)                    u.grado = b.grado;
  if (b.institucion)              u.institucion = b.institucion;
  if (b.municipio != null)        u.municipio = b.municipio;
  if (b.telefono != null)         u.telefono = b.telefono;
  if (b.fechaNacimiento != null)  u.fechaNacimiento = b.fechaNacimiento;
  if (b.bio != null)              u.bio = b.bio;
  if (b.intereses != null)        u.intereses = b.intereses;
  if (b.directorGrupo != null)    u.directorGrupo = b.directorGrupo;
  writeJSON(DB_FILE, db);
  res.json({ ok: true, user: {
    username: u.username, name: u.name, emoji: u.emoji, role: u.role,
    grado: u.grado, institucion: u.institucion, directorGrupo: u.directorGrupo || ''
  }});
});

// ── RECURSOS ──────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

app.get('/api/recursos', authRequired, (req, res) => {
  res.json({ recursos: db.recursos || [] });
});

app.post('/api/recursos/upload', authRequired, upload.single('archivo'), (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  if (!req.file) return res.status(400).json({ error: 'Sin archivo' });
  if (!db.recursos) db.recursos = [];
  const rec = {
    id: Date.now().toString(),
    titulo: req.body.titulo || req.file.originalname,
    url: '/uploads/' + req.file.filename,
    mimeType: req.file.mimetype,
    tipo: req.file.mimetype,
    size: req.file.size,
    modulo: req.body.modulo || 'general',
    fecha: new Date().toLocaleString('es-CO', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' }),
    subidoPor: req.username,
    ts: new Date().toISOString()
  };
  db.recursos.push(rec);
  writeJSON(DB_FILE, db);
  res.json({ ok: true, recurso: rec });
});

app.post('/api/perfil/foto', authRequired, upload.single('foto'), (req, res) => {
  const u = db.users[req.username];
  if (!u) return res.status(404).json({ error: 'No encontrado' });
  if (!req.file) return res.status(400).json({ error: 'Sin foto' });
  u.fotoUrl = '/uploads/' + req.file.filename;
  writeJSON(DB_FILE, db);
  res.json({ ok: true, fotoUrl: u.fotoUrl });
});

app.delete('/api/recursos/:id', authRequired, (req, res) => {
  const tutorU = db.users[req.username];
  if (!tutorU || tutorU.role !== 'tutor') return res.status(403).json({ error: 'Solo docentes' });
  db.recursos = (db.recursos || []).filter(r => r.id !== req.params.id);
  writeJSON(DB_FILE, db);
  res.json({ ok: true });
});

// ── QUIZ ──────────────────────────────────────────────────────
app.post('/api/quiz', authRequired, (req, res) => {
  const { modulo, score, total } = req.body || {};
  if (!db.actividad) db.actividad = [];
  const pct = total > 0 ? Math.round((score / total) * 100) : 0;
  db.actividad.push({
    username: req.username, tipo: 'quiz', modulo,
    detalle: `${score}/${total} (${pct}%)`, pct,
    ts: new Date().toISOString()
  });
  if (db.users[req.username]) db.users[req.username].ultimaConexion = new Date().toISOString();
  writeJSON(DB_FILE, db);
  writeJSON(ACT_FILE, db.actividad);
  res.json({ ok: true, pct });
});

// ── RESULTADOS DE SIMULACROS ──────────────────────────────────
// Guardar el resultado de un simulacro (lo envía el estudiante al terminar)
app.post('/api/resultado', authRequired, (req, res) => {
  const { modulo, score, total, pct, duracion, respuestas } = req.body || {};
  const u = db.users[req.username] || {};

  const sc  = Number(score) || 0;
  const tot = Number(total) || 0;
  const porc = (pct != null) ? Number(pct) : (tot > 0 ? Math.round((sc / tot) * 100) : 0);

  const rec = {
    username: req.username,
    nombre:   u.name  || req.username,
    emoji:    u.emoji || '👤',
    modulo:   modulo || 'general',
    score:    sc,
    total:    tot,
    pct:      porc,
    duracion: duracion != null ? Number(duracion) : 0,
    respuestas: Array.isArray(respuestas) ? respuestas : [],
    fecha:    new Date().toLocaleString('es-CO'),
    ts:       new Date().toISOString()
  };

  if (!db.resultados) db.resultados = [];
  db.resultados.push(rec);
  if (db.resultados.length > 1000) db.resultados.splice(0, db.resultados.length - 1000);

  // También se registra en actividad para que el dashboard calcule promedios
  if (!db.actividad) db.actividad = [];
  db.actividad.push({
    username: req.username, tipo: 'quiz', modulo: rec.modulo,
    detalle: `${rec.score}/${rec.total} (${rec.pct}%)`, pct: rec.pct, ts: rec.ts
  });
  if (db.users[req.username]) db.users[req.username].ultimaConexion = new Date().toISOString();

  writeJSON(DB_FILE, db);
  writeJSON(ACT_FILE, db.actividad);
  res.json({ ok: true, pct: rec.pct, resultado: rec });
});

// Listar resultados: el docente ve todos; el estudiante solo los suyos
app.get('/api/resultados', authRequired, (req, res) => {
  const u = db.users[req.username];
  let lista = db.resultados || [];
  if (!u || u.role !== 'tutor') {
    lista = lista.filter(r => r.username === req.username);
  }
  // Más recientes primero
  lista = lista.slice().sort((a, b) => (b.ts || '').localeCompare(a.ts || ''));
  res.json({ resultados: lista });
});

app.all('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// ── Catch-all para SPA (Rutas estáticas seguras para Bonto) ───
app.get('*', (req, res) => {
  res.sendFile('index.html', { root: __dirname });
});

// ── Arrancar servidor ─────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🌿 SABER RURAL corriendo en puerto ${PORT}`);
});