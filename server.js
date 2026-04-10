const express    = require('express');
const cors       = require('cors');
const compress   = require('compression');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const Database   = require('better-sqlite3');
const path       = require('path');
const fs         = require('fs');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vases-cana-secret-change-me-in-production';
const DATA_DIR   = process.env.DATA_DIR || path.join(__dirname, 'data');
const PIN_HASH   = process.env.PIN_HASH || '';  // bcrypt hash of the user's PIN

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'sync.db'));

// ── DATABASE INIT ─────────────────────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode=WAL;

  CREATE TABLE IF NOT EXISTS sync_data (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT    NOT NULL,
    data_type   TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    synced_at   TEXT    DEFAULT (datetime('now')),
    UNIQUE(device_id, data_type)
  );

  CREATE TABLE IF NOT EXISTS sync_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT,
    action      TEXT,
    ts          TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Store PIN hash on first run if provided via env
if (PIN_HASH) {
  db.prepare('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)').run('pin_hash', PIN_HASH);
}

// ── APP SETUP ─────────────────────────────────────────────────────────────────
const app = express();
app.use(compress());
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '10mb' }));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET);
    req.deviceId = decoded.deviceId;
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
}

function log(deviceId, action) {
  db.prepare('INSERT INTO sync_log (device_id,action) VALUES (?,?)').run(deviceId||'unknown', action);
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    app: 'Les 6 Vases de Cana — Sync Server',
    version: '1.0.0',
    time: new Date().toISOString()
  });
});

// ── SETUP PIN (première configuration) ──
app.post('/setup', async (req, res) => {
  const { pin } = req.body;
  if (!pin || pin.length < 4) return res.status(400).json({ error: 'PIN trop court (minimum 4 chiffres)' });

  const existing = db.prepare('SELECT value FROM config WHERE key=?').get('pin_hash');
  if (existing) return res.status(409).json({ error: 'PIN déjà configuré. Utilise /reset-pin pour le changer.' });

  const hash = await bcrypt.hash(pin, 10);
  db.prepare('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)').run('pin_hash', hash);
  log('setup', 'PIN configuré');
  res.json({ ok: true, message: 'PIN configuré avec succès !' });
});

// ── LOGIN avec PIN → JWT ──
app.post('/login', async (req, res) => {
  const { pin, deviceId, deviceName } = req.body;
  if (!pin) return res.status(400).json({ error: 'PIN requis' });

  const cfg = db.prepare('SELECT value FROM config WHERE key=?').get('pin_hash');
  if (!cfg) return res.status(503).json({ error: 'Serveur non configuré. Va sur /setup d\'abord.' });

  const valid = await bcrypt.compare(String(pin), cfg.value);
  if (!valid) {
    log(deviceId, 'login_fail');
    return res.status(401).json({ error: 'PIN incorrect' });
  }

  const token = jwt.sign(
    { deviceId: deviceId || 'unknown', deviceName: deviceName || 'Appareil' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  log(deviceId, `login_ok:${deviceName||'?'}`);
  res.json({ ok: true, token, message: 'Connecté !' });
});

// ── PUSH : envoyer les données depuis un appareil ──
app.post('/sync/push', requireAuth, (req, res) => {
  const { dataTypes } = req.body; // { vases: [...], daily_checks: [...], goals: [...], finance: {...} }
  if (!dataTypes) return res.status(400).json({ error: 'Données manquantes' });

  const upsert = db.prepare('INSERT OR REPLACE INTO sync_data (device_id,data_type,payload,synced_at) VALUES (?,?,?,datetime("now"))');
  const tx = db.transaction(() => {
    Object.entries(dataTypes).forEach(([type, data]) => {
      upsert.run(req.deviceId, type, JSON.stringify(data));
    });
  });
  tx();
  log(req.deviceId, `push:${Object.keys(dataTypes).join(',')}`);
  res.json({ ok: true, synced_at: new Date().toISOString() });
});

// ── PULL : récupérer les données les plus récentes (tous appareils confondus) ──
app.get('/sync/pull', requireAuth, (req, res) => {
  const types = ['vases','daily_checks','goals','finance_accounts','finance_entries','settings'];
  const result = {};

  types.forEach(type => {
    // Get the most recently synced version of each type
    const row = db.prepare(
      'SELECT payload, device_id, synced_at FROM sync_data WHERE data_type=? ORDER BY synced_at DESC LIMIT 1'
    ).get(type);
    if (row) {
      result[type] = {
        data: JSON.parse(row.payload),
        from_device: row.device_id,
        synced_at: row.synced_at
      };
    }
  });

  log(req.deviceId, 'pull');
  res.json({ ok: true, data: result, pulled_at: new Date().toISOString() });
});

// ── STATUS : info sur les syncs ──
app.get('/sync/status', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT data_type, device_id, synced_at FROM sync_data ORDER BY synced_at DESC'
  ).all();
  const logs = db.prepare('SELECT * FROM sync_log ORDER BY ts DESC LIMIT 20').all();
  res.json({ ok: true, syncEntries: rows, recentLogs: logs });
});

// ── RESET PIN ──
app.post('/reset-pin', requireAuth, async (req, res) => {
  const { newPin } = req.body;
  if (!newPin || newPin.length < 4) return res.status(400).json({ error: 'Nouveau PIN trop court' });
  const hash = await bcrypt.hash(String(newPin), 10);
  db.prepare('INSERT OR REPLACE INTO config (key,value) VALUES (?,?)').run('pin_hash', hash);
  log(req.deviceId, 'pin_reset');
  res.json({ ok: true, message: 'PIN mis à jour' });
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Vases de Cana Sync Server — port ${PORT}`);
  console.log(`📡 Health: http://localhost:${PORT}/`);
  const hasPIN = !!db.prepare('SELECT value FROM config WHERE key=?').get('pin_hash');
  if (!hasPIN) console.log(`⚠️  PIN non configuré — POST /setup avec {"pin":"XXXX"}`);
  else console.log(`🔒 PIN configuré`);
});
