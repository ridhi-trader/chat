// Raazdaar server. Sees ONLY encrypted blobs. Never sees passcode, key, or message text.
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname; // Railway volume / Render disk path
const DATA_FILE = process.env.DATA_FILE || path.join(DATA_DIR, 'data_store.json');
const MEDIA_DIR = path.join(DATA_DIR, 'media');
fs.mkdirSync(MEDIA_DIR, { recursive: true });
const MAX_USERS = parseInt(process.env.MAX_USERS || '3', 10);          // people per room
const TTL_HOURS = parseInt(process.env.TTL_HOURS || '0', 10);           // 0 = kabhi delete nahi (hamesha save)
const TTL_MS = TTL_HOURS * 3600 * 1000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 12e6 });

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ---------- storage ----------
// rooms[id] = { salt, authHash, createdAt, messages: [...] }
// Sab kuch (text + photo + voice) server disk pe ENCRYPTED save hota hai. Phone pe kuch nahi.
let db = { rooms: {} };
try { if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { db = { rooms: {} }; }
if (!db.rooms) db.rooms = {};
const media = {}; // roomId -> [messages]
const rdir = (id) => path.join(MEDIA_DIR, sha(id).slice(0, 32));
try {
  fs.readdirSync(MEDIA_DIR).forEach((d) => {
    fs.readdirSync(path.join(MEDIA_DIR, d)).forEach((f) => {
      try { const m = JSON.parse(fs.readFileSync(path.join(MEDIA_DIR, d, f), 'utf8')); (media[m.room] = media[m.room] || []).push(m); } catch (e) {}
    });
  });
} catch (e) {}

let saveTimer = null;
function saveMedia(id) {
  (media[id] || []).forEach((m) => { try { fs.writeFileSync(path.join(rdir(id), m.id + '.json'), JSON.stringify(m)); } catch (e) {} });
}
function saveSoon() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(db), 'utf8'); } catch (e) {}
  }, 300);
}

const presence = {}; // roomId -> { socketId: { clientId, name } }
const fails = {};    // roomId -> { n, until }

const cleanRoom = (r) => String(r || '').trim().toLowerCase().slice(0, 64);
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);

function getOrCreateRoom(id) {
  let room = db.rooms[id];
  if (!room) {
    room = { salt: crypto.randomBytes(16).toString('hex'), authHash: null, createdAt: Date.now(), messages: [] };
    db.rooms[id] = room;
    saveSoon();
  }
  return room;
}
function allMessages(id) {
  const room = db.rooms[id];
  if (!room) return [];
  return room.messages.concat(media[id] || []).sort((a, b) => a.ts - b.ts);
}
function pub(m) {
  return { id: m.id, kind: m.kind, iv: m.iv, data: m.data, from: m.from, ts: m.ts, status: m.status };
}
function users(id) {
  const p = presence[id] || {};
  return Object.entries(p).map(([sid, u]) => ({ sid, cid: u.clientId, name: u.name }));
}

// ---------- socket ----------
io.on('connection', (socket) => {
  socket.on('request-room', (d, cb) => {
    const id = cleanRoom(d && d.roomId);
    if (!id) return cb && cb({ error: 'Room ID required' });
    const room = getOrCreateRoom(id);
    cb && cb({ salt: room.salt });
  });

  socket.on('join-room', (d, cb) => {
    d = d || {};
    const id = cleanRoom(d.roomId);
    if (!id) return cb && cb({ error: 'Room ID required' });
    if (!isHex(d.authHash, 64)) return cb && cb({ error: 'Passcode required' });
    const clientId = String(d.clientId || '').slice(0, 40);
    const name = String(d.name || 'Dost').trim().slice(0, 24) || 'Dost';
    if (!clientId) return cb && cb({ error: 'Bad client' });

    const f = fails[id] || { n: 0, until: 0 };
    if (Date.now() < f.until) return cb && cb({ error: 'Bahut galat try. Thodi der ruk ke dobara.' });

    const room = getOrCreateRoom(id);
    const h = sha(d.authHash);
    if (room.authHash === null) { room.authHash = h; saveSoon(); }
    else if (room.authHash !== h) {
      f.n += 1; if (f.n >= 5) { f.until = Date.now() + 30000; f.n = 0; }
      fails[id] = f;
      return cb && cb({ error: 'Incorrect Passcode!' });
    }
    fails[id] = { n: 0, until: 0 };

    presence[id] = presence[id] || {};
    const sameClient = Object.entries(presence[id]).filter(([, u]) => u.clientId === clientId).map(([sid]) => sid);
    const distinct = new Set(Object.values(presence[id]).map((u) => u.clientId));
    if (!distinct.has(clientId) && distinct.size >= MAX_USERS) return cb && cb({ error: 'Room full (max ' + MAX_USERS + ')' });
    sameClient.forEach((sid) => { delete presence[id][sid]; });

    socket.join(id);
    socket.roomId = id; socket.clientId = clientId;
    presence[id][socket.id] = { clientId, name };

    // messages from others that were "sent" are now "delivered"
    let changed = false;
    allMessages(id).forEach((m) => { if (m.from !== clientId && m.status === 'sent') { m.status = 'delivered'; changed = true; } });
    if (changed) { saveSoon(); saveMedia(id); socket.to(id).emit('status-update', { by: clientId, status: 'delivered' }); }

    cb && cb({ success: true, salt: room.salt, history: allMessages(id).map(pub), users: users(id), ttlHours: TTL_HOURS });
    io.to(id).emit('room-users', { users: users(id) });
  });

  socket.on('send', (d, cb) => {
    const id = socket.roomId;
    if (!id || !db.rooms[id]) return cb && cb({ error: 'Not in room' });
    if (!d || typeof d.iv !== 'string' || typeof d.data !== 'string' || !d.id) return cb && cb({ error: 'Bad message' });
    const kind = d.kind === 'media' ? 'media' : 'text';
    const mid = String(d.id).slice(0, 40);
    const exists = allMessages(id).find((m) => m.id === mid);
    if (exists) return cb && cb({ ok: true, status: exists.status, ts: exists.ts });

    const others = users(id).filter((u) => u.cid !== socket.clientId).length;
    const m = { id: mid, kind, iv: d.iv.slice(0, 32), data: d.data, from: socket.clientId, ts: Date.now(), status: others ? 'delivered' : 'sent' };
    if (kind === 'media') {
      m.room = id; (media[id] = media[id] || []).push(m);
      try { fs.mkdirSync(rdir(id), { recursive: true }); fs.writeFileSync(path.join(rdir(id), m.id + '.json'), JSON.stringify(m)); } catch (e) {}
    } else {
      db.rooms[id].messages.push(m);
      saveSoon();
    }
    io.to(id).emit('msg', pub(m));
    cb && cb({ ok: true, status: m.status, ts: m.ts });
  });

  socket.on('seen', () => {
    const id = socket.roomId;
    if (!id) return;
    let changed = false;
    allMessages(id).forEach((m) => { if (m.from !== socket.clientId && m.status !== 'seen') { m.status = 'seen'; changed = true; } });
    if (changed) { saveSoon(); saveMedia(id); socket.to(id).emit('status-update', { by: socket.clientId, status: 'seen' }); }
  });

  socket.on('typing', (v) => { if (socket.roomId) socket.to(socket.roomId).emit('typing', { cid: socket.clientId, on: !!v }); });

  // WebRTC signalling (relay only)
  ['call-offer', 'call-answer', 'call-ice', 'call-end', 'call-reject'].forEach((ev) => {
    socket.on(ev, (d) => {
      if (!d || !d.to || !socket.roomId) return;
      const p = presence[socket.roomId] || {};
      if (!p[d.to]) return;
      io.to(d.to).emit(ev, Object.assign({}, d, { from: socket.id }));
    });
  });

  socket.on('leave-room', () => leave(socket));
  socket.on('disconnect', () => leave(socket));
});

function leave(socket) {
  const id = socket.roomId;
  if (!id) return;
  if (presence[id]) { delete presence[id][socket.id]; if (!Object.keys(presence[id]).length) delete presence[id]; }
  socket.leave(id);
  socket.roomId = null;
  io.to(id).emit('room-users', { users: users(id) });
}

// ---------- auto delete ----------
function sweep() {
  if (!TTL_MS) return;
  const cutoff = Date.now() - TTL_MS;
  let changed = false;
  Object.keys(db.rooms).forEach((id) => {
    const r = db.rooms[id];
    const before = r.messages.length;
    r.messages = r.messages.filter((m) => m.ts > cutoff);
    if (r.messages.length !== before) changed = true;
    if (media[id]) media[id] = media[id].filter((m) => m.ts > cutoff);
    // empty, unused, old rooms vanish
    if (!r.messages.length && !(media[id] || []).length && !presence[id] && Date.now() - r.createdAt > TTL_MS) { delete db.rooms[id]; changed = true; }
  });
  if (changed) saveSoon();
}
setInterval(sweep, 10 * 60 * 1000).unref();
sweep();

server.listen(PORT, '0.0.0.0', () => {
  console.log('==============================================');
  console.log('  Raazdaar chal raha hai!');
  console.log('  Browser mein kholo:  http://localhost:' + PORT);
  console.log('  Server sirf encrypted data dekhta hai.');
  console.log('  Is window ko band mat karo.');
  console.log('==============================================');
});
