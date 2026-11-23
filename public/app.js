/* Raazdaar client. All crypto happens here. Passcode/key never leave this device. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var enc = new TextEncoder(), dec = new TextDecoder();

  // ---------- state (memory only; chat is NEVER written to localStorage/IndexedDB) ----------
  var S = {
    sock: null, key: null, authHash: null, salt: null,
    nick: '', roomId: '', passcode: '', clientId: '',
    msgs: [], byId: {}, queue: [], users: [], shown: 50,
    joined: false, locked: false, typingT: null, lastTypingSent: 0,
    peers: {}, nameByCid: {}
  };
  var PAGE = 50;

  // theme is harmless, the only thing we keep
  try { var th = localStorage.getItem('rz-theme'); if (th) document.body.dataset.theme = th; } catch (e) {}

  // ---------- helpers ----------
  function toast(t, ms) { var el = $('toast'); el.textContent = t; el.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(function () { el.hidden = true; }, ms || 2800); }
  function b64(buf) { var b = new Uint8Array(buf), s = '', i, c = 0x8000; for (i = 0; i < b.length; i += c) s += String.fromCharCode.apply(null, b.subarray(i, i + c)); return btoa(s); }
  function unb64(s) { var bin = atob(s), u = new Uint8Array(bin.length), i; for (i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }
  function unhex(h) { var u = new Uint8Array(h.length / 2), i; for (i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; }
  function uid() { var a = new Uint8Array(10); crypto.getRandomValues(a); return hex(a); }
  function fmtTime(ts) { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  // ---------- crypto ----------
  // passcode --PBKDF2(200k, salt from server)--> 64 bytes: first 32 = login proof, last 32 = AES-GCM key.
  // Server only ever gets the proof (and stores a hash OF it). It cannot derive the key.
  function deriveAll(pass, saltHex) {
    if (!(window.crypto && crypto.subtle)) return Promise.reject(new Error('Secure page chahiye (HTTPS ya localhost).'));
    return crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']).then(function (km) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unhex(saltHex), iterations: 200000, hash: 'SHA-256' }, km, 512);
    }).then(function (bits) {
      var u = new Uint8Array(bits);
      return crypto.subtle.importKey('raw', u.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']).then(function (key) {
        return { authHash: hex(u.slice(0, 32)), key: key };
      });
    });
  }
  function encryptObj(obj) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, S.key, enc.encode(JSON.stringify(obj))).then(function (ct) { return { iv: b64(iv), data: b64(ct) }; });
  }
  function decryptObj(iv, data) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, S.key, unb64(data)).then(function (pt) { return JSON.parse(dec.decode(pt)); });
  }

  // ---------- login ----------
  $('eye').onclick = function () { var p = $('pass'); p.type = p.type === 'password' ? 'text' : 'password'; };
  $('pass').addEventListener('input', function () {
    var v = this.value, sc = Math.min(100, v.length * 6 + (/\s/.test(v) ? 15 : 0) + (/\d/.test(v) ? 8 : 0));
    var i = $('strength'); i.innerHTML = '<i style="width:' + sc + '%;background:' + (sc < 40 ? 'var(--red)' : sc < 70 ? '#ffb020' : 'var(--ok)') + '"></i>';
  });
  // identity is derived (nothing stored on the phone): same nickname + passcode = same person, every time

  $('loginForm').addEventListener('submit', function (e) {
    e.preventDefault();
    S.nick = $('nick').value.trim(); S.roomId = $('room').value.trim().toLowerCase(); S.passcode = $('pass').value;
    if (S.passcode.length < 4) { $('loginErr').textContent = 'Passcode kam se kam 4 akshar ka ho.'; return; }
    $('loginErr').textContent = ''; $('enterBtn').disabled = true; $('enterBtn').textContent = 'Ruko…';
    connect().then(function () { return joinRoom(); }).then(showChat).catch(function (err) {
      $('loginErr').textContent = err && err.message ? err.message : String(err);
      $('enterBtn').disabled = false; $('enterBtn').textContent = 'Andar jao';
      if (S.sock) { try { S.sock.emit('leave-room'); S.sock.disconnect(); } catch (e2) {} S.sock = null; }
    });
  });

  function connect() {
    return new Promise(function (res, rej) {
      if (typeof io === 'undefined') return rej(new Error('Server se connect nahi ho paya.'));
      S.sock = io({ transports: ['websocket', 'polling'], reconnection: true, reconnectionDelay: 700, reconnectionDelayMax: 5000, timeout: 8000 });
      var done = false;
      S.sock.once('connect', function () { done = true; res(); bind(); });
      S.sock.once('connect_error', function () { if (!done) rej(new Error('Server se connect nahi ho paya. Server chal raha hai?')); });
    });
  }
  function emitAck(ev, data, ms) {
    return new Promise(function (res, rej) {
      var t = setTimeout(function () { rej(new Error('timeout')); }, ms || 8000);
      S.sock.emit(ev, data, function (r) { clearTimeout(t); res(r); });
    });
  }
  function joinRoom() {
    return emitAck('request-room', { roomId: S.roomId }).then(function (r) {
      if (r.error) throw new Error(r.error);
      S.salt = r.salt;
      if (S.authHash && S.key) return;
      return deriveAll(S.passcode, S.salt).then(function (d) { S.authHash = d.authHash; S.key = d.key; return crypto.subtle.digest('SHA-256', enc.encode(d.authHash + '|' + S.nick.toLowerCase())).then(function (h) { S.clientId = hex(h).slice(0, 24); }); });
    }).then(function () {
      return emitAck('join-room', { roomId: S.roomId, authHash: S.authHash, clientId: S.clientId, name: S.nick });
    }).then(function (r) {
      if (r.error) { S.authHash = null; S.key = null; throw new Error(r.error); }
      S.users = r.users || []; S.ttl = r.ttlHours;
      return loadHistory(r.history || []);
    });
  }
  function loadHistory(hist) {
    var known = {}; S.msgs.forEach(function (m) { known[m.id] = 1; });
    var fresh = hist.filter(function (h) { return !known[h.id]; });
    return Promise.all(fresh.map(function (h) { return ingest(h, true); })).then(function () {
      // refresh status of known messages
      hist.forEach(function (h) { var m = S.byId[h.id]; if (m) m.status = h.status; });
      sortMsgs();
    });
  }

  // ---------- messages ----------
  function ingest(h, quiet) {
    return decryptObj(h.iv, h.data).then(function (p) {
      var m = { id: h.id, from: h.from, ts: h.ts, status: h.status, p: p, mine: h.from === S.clientId };
      if (p.name) S.nameByCid[h.from] = p.name;
      if (!S.byId[m.id]) { S.byId[m.id] = m; S.msgs.push(m); }
      else { S.byId[m.id].status = h.status; S.byId[m.id].pending = false; }
      return m;
    }).catch(function () {
      var m = { id: h.id, from: h.from, ts: h.ts, status: h.status, p: { t: 'text', text: '🔒 Decrypt nahi hua' }, mine: h.from === S.clientId };
      if (!S.byId[m.id]) { S.byId[m.id] = m; S.msgs.push(m); }
    });
  }
  function sortMsgs() { S.msgs.sort(function (a, b) { return a.ts - b.ts; }); render(); }

  function sendPayload(p) {
    p.name = S.nick;
    var id = uid(), kind = p.t === 'text' ? 'text' : 'media';
    var m = { id: id, from: S.clientId, ts: Date.now(), status: 'pending', p: p, mine: true, pending: true };
    S.byId[id] = m; S.msgs.push(m); render(true);
    return encryptObj(p).then(function (e) {
      m.wire = { id: id, kind: kind, iv: e.iv, data: e.data };
      S.queue.push(m); flush();
    });
  }
  var flushing = false;
  function flush() {
    if (flushing || !S.sock || !S.sock.connected || !S.joined) return;
    var m = S.queue[0];
    if (!m) return;
    flushing = true;
    emitAck('send', m.wire, 10000).then(function (r) {
      flushing = false;
      if (r && r.ok) { m.pending = false; m.status = r.status; m.ts = r.ts || m.ts; m.wire = null; S.queue.shift(); render(); flush(); }
      else { toast((r && r.error) || 'Nahi gaya'); S.queue.shift(); m.status = 'failed'; render(); flush(); }
    }).catch(function () { flushing = false; /* retry on next reconnect/tick */ setTimeout(flush, 2500); });
  }

  // ---------- socket events ----------
  var bound = false;
  function bind() {
    if (bound) return; bound = true;
    var s = S.sock;
    s.on('msg', function (h) {
      if (S.byId[h.id] && S.byId[h.id].mine) { S.byId[h.id].status = h.status; render(); return; }
      ingest(h).then(function () { sortMsgs(); if (h.from !== S.clientId) { if (document.visibilityState === 'visible' && !S.locked) s.emit('seen'); else notify(); } });
    });
    s.on('status-update', function (d) {
      var rank = { pending: 0, sent: 1, delivered: 2, seen: 3 };
      S.msgs.forEach(function (m) { if (m.mine && (rank[m.status] || 0) < rank[d.status]) m.status = d.status; });
      render();
    });
    s.on('room-users', function (d) { S.users = d.users || []; header(); });
    s.on('typing', function (d) { if (d.cid === S.clientId) return; var t = $('typing'); t.hidden = !d.on; t.textContent = d.on ? (S.nameByCid[d.cid] || 'Koi') + ' likh raha hai…' : ''; clearTimeout(S.typingT); if (d.on) S.typingT = setTimeout(function () { t.hidden = true; }, 4000); });
    s.on('disconnect', function () { S.joined = false; $('netBanner').hidden = false; });
    s.io.on('reconnect', function () { rejoin(); });
    s.on('connect', function () { if (S.key) rejoin(); });
    // calls
    s.on('call-offer', onOffer); s.on('call-answer', onAnswer); s.on('call-ice', onIce);
    s.on('call-end', function () { endCall(true); toast('Call khatam'); });
    s.on('call-reject', function () { endCall(true); toast('Call kaat di'); });
  }
  var rejoining = false;
  function rejoin() {
    if (rejoining || !S.key) return; rejoining = true;
    emitAck('join-room', { roomId: S.roomId, authHash: S.authHash, clientId: S.clientId, name: S.nick }).then(function (r) {
      rejoining = false;
      if (r.error) { toast(r.error); return; }
      S.joined = true; $('netBanner').hidden = true; S.users = r.users || [];
      return loadHistory(r.history).then(function () { header(); flush(); if (document.visibilityState === 'visible' && !S.locked) S.sock.emit('seen'); });
    }).catch(function () { rejoining = false; setTimeout(rejoin, 2000); });
  }
  window.addEventListener('online', function () { $('netBanner').hidden = !(S.sock && !S.sock.connected); if (S.sock && !S.sock.connected) S.sock.connect(); });
  window.addEventListener('offline', function () { $('netBanner').hidden = false; });

  function notify() { try { if (navigator.vibrate) navigator.vibrate(60); } catch (e) {} }

  // ---------- render ----------
  var tickSvg = function (id) { return '<svg viewBox="0 0 ' + (id === 'i-tick2' ? '20' : '16') + ' 16"><use href="#' + id + '"/></svg>'; };
  function statusIcon(m) {
    if (!m.mine) return '';
    if (m.status === 'pending') return tickSvg('i-clock');
    if (m.status === 'failed') return '<span style="color:var(--red)">!</span>';
    if (m.status === 'sent') return tickSvg('i-tick');
    if (m.status === 'delivered') return tickSvg('i-tick2');
    return '<span class="seen">' + tickSvg('i-tick2') + '</span>';
  }
  function bodyHtml(m) {
    var p = m.p || {};
    if (p.t === 'image') return '<img class="pic" alt="photo" src="' + p.url + '">' + (p.text ? '<div>' + esc(p.text) + '</div>' : '');
    if (p.t === 'voice') return '<audio controls preload="metadata" src="' + p.url + '"></audio>';
    if (p.t === 'file') return '<a class="fl" download="' + esc(p.fileName || 'file') + '" href="' + p.url + '"><svg viewBox="0 0 24 24"><use href="#i-file"/></svg>' + esc(p.fileName || 'file') + '</a>';
    return esc(p.text || '');
  }
  function mediaUrl(m) { var p = m.p; if (p && p.data && !p.url) { try { var bin = unb64(p.data); p.url = URL.createObjectURL(new Blob([bin], { type: p.mime || 'application/octet-stream' })); } catch (e) {} } }
  function render(stick) {
    var box = $('msgs'); if (!S.joined && !S.msgs.length && $('chat').classList.contains('active') === false) return;
    var atBottom = stick || box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    var list = S.msgs, start = Math.max(0, list.length - S.shown), h = '';
    if (start > 0) h += '<button class="more" id="moreBtn">Purane messages (' + start + ')</button>';
    var lastDay = '';
    for (var i = start; i < list.length; i++) {
      var m = list[i]; mediaUrl(m);
      var day = new Date(m.ts).toLocaleDateString([], { day: 'numeric', month: 'short' });
      if (day !== lastDay) { h += '<div class="sys">' + day + '</div>'; lastDay = day; }
      h += '<div class="m' + (m.mine ? ' mine' : '') + '">' + (!m.mine ? '<div class="who">' + esc((m.p && m.p.name) || 'Dost') + '</div>' : '') + bodyHtml(m) +
        '<div class="meta"><span>' + fmtTime(m.ts) + '</span>' + statusIcon(m) + '</div></div>';
    }
    box.innerHTML = h;
    var mb = $('moreBtn'); if (mb) mb.onclick = function () { S.shown += PAGE; render(); };
    if (atBottom) box.scrollTop = box.scrollHeight;
  }
  function header() {
    $('roomName').textContent = '🔒 ' + S.roomId;
    var n = new Set(S.users.map(function (u) { return u.cid; })).size;
    var others = S.users.filter(function (u) { return u.cid !== S.clientId; });
    $('onlineTxt').textContent = others.length ? others.map(function (u) { return u.name; }).join(', ') + ' online' : 'Akela (' + n + ' online)';
    $('ttlTxt').textContent = S.ttl ? 'Server pe messages ' + S.ttl + ' ghante baad mit jaate hain.' : 'Chat server pe safe rehti hai, phone pe kuch save nahi hota.';
  }
  function showChat() {
    S.joined = true;
    $('login').classList.remove('active'); $('chat').classList.add('active');
    $('pass').value = ''; S.passcode = '';  // don't keep passcode text around
    header(); render(true); flush();
    if (S.sock) S.sock.emit('seen');
  }
  $('leaveBtn').onclick = function () { leaveAll(); };
  function leaveAll() {
    try { S.sock.emit('leave-room'); S.sock.disconnect(); } catch (e) {}
    endCall(true);
    S.msgs = []; S.byId = {}; S.queue = []; S.key = null; S.authHash = null; S.joined = false; S.sock = null; bound = false; $('msgs').innerHTML = '';
    $('chat').classList.remove('active'); $('login').classList.add('active');
    $('enterBtn').disabled = false; $('enterBtn').textContent = 'Andar jao';
  }
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'visible' && S.joined && !S.locked && S.sock) S.sock.emit('seen'); if (document.visibilityState === 'hidden') hiddenAt = Date.now(); else autoLockCheck(); });

  // ---------- composer ----------
  var ta = $('text');
  function syncBtns() { var has = ta.value.trim().length > 0; $('sendBtn').hidden = !has; $('micBtn').hidden = has; }
  ta.addEventListener('input', function () {
    ta.style.height = 'auto'; ta.style.height = Math.min(120, ta.scrollHeight) + 'px'; syncBtns();
    var now = Date.now(); if (S.sock && now - S.lastTypingSent > 2000) { S.lastTypingSent = now; S.sock.emit('typing', true); setTimeout(function () { S.sock && S.sock.emit('typing', false); }, 2500); }
  });
  ta.addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.shiftKey && window.innerWidth > 700) { e.preventDefault(); $('composer').requestSubmit(); } });
  $('composer').addEventListener('submit', function (e) {
    e.preventDefault(); var v = ta.value.trim(); if (!v) return;
    ta.value = ''; ta.style.height = 'auto'; syncBtns(); $('emojiPanel').hidden = true;
    sendPayload({ t: 'text', text: v });
  });
  syncBtns();

  // emoji
  var EMO = {
    '😀': '😀 😃 😄 😁 😆 😅 😂 🤣 😊 😇 🙂 😉 😍 🥰 😘 😗 😋 😛 😜 🤪 🤗 🤭 🤔 😏 😌 😴 😎 🤓 😢 😭 😤 😡 🥺 😱 🤯 😳 🥳 🤩 🙄 😬 🫠'.split(' '),
    '🐼': '🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🐔 🐧 🐦 🦄 🐝 🦋 🐢 🐙 🐬 🐳 🌸 🌼 🌻 🌹 🍀'.split(' '),
    '🍕': '🍕 🍔 🍟 🌭 🍿 🍩 🍪 🎂 🍰 🍫 🍬 🍭 🍎 🍓 🍉 🍇 🍌 🥭 ☕ 🍵 🧋 🥤 🍜 🍣 🍦 🥪 🌮 🍳'.split(' '),
    '❤️': '❤️ 🧡 💛 💚 💙 💜 🖤 🤍 💖 💗 💓 💞 💕 💘 💝 ✨ 🌟 ⭐ 🔥 🎉 🎈 🎁 💯 👍 👎 👏 🙌 🙏 💪 🤝 👋 🤞 ✌️ 🫶'.split(' ')
  };
  (function () {
    var tabs = $('emojiTabs'), grid = $('emojiGrid');
    Object.keys(EMO).forEach(function (k, i) {
      var b = document.createElement('button'); b.type = 'button'; b.textContent = k; if (!i) b.className = 'on';
      b.onclick = function () { Array.prototype.forEach.call(tabs.children, function (x) { x.className = ''; }); b.className = 'on'; fill(k); };
      tabs.appendChild(b);
    });
    function fill(k) { grid.innerHTML = ''; EMO[k].forEach(function (em) { var b = document.createElement('button'); b.type = 'button'; b.textContent = em; b.onclick = function () { ta.value += em; ta.dispatchEvent(new Event('input')); ta.focus(); }; grid.appendChild(b); }); }
    fill(Object.keys(EMO)[0]);
  })();
  $('emojiBtn').onclick = function () { $('emojiPanel').hidden = !$('emojiPanel').hidden; };

  // attachments
  $('attachBtn').onclick = function () { $('fileIn').click(); };
  $('fileIn').addEventListener('change', function () {
    var f = this.files[0]; this.value = ''; if (!f) return;
    if (f.size > 8 * 1024 * 1024) return toast('File 8MB se badi hai');
    if (/^image\//.test(f.type)) shrinkImage(f).then(function (r) { sendPayload({ t: 'image', mime: r.mime, data: r.data }); }).catch(function () { toast('Photo nahi khuli'); });
    else f.arrayBuffer().then(function (buf) { sendPayload({ t: 'file', mime: f.type || 'application/octet-stream', fileName: f.name.slice(0, 100), data: b64(buf) }); });
  });
  // photos are shrunk (saves net) and re-encoded (strips location/EXIF)
  function shrinkImage(file) {
    return new Promise(function (res, rej) {
      var img = new Image(), u = URL.createObjectURL(file);
      img.onload = function () {
        var max = 1280, s = Math.min(1, max / Math.max(img.width, img.height)), c = document.createElement('canvas');
        c.width = Math.round(img.width * s); c.height = Math.round(img.height * s);
        c.getContext('2d').drawImage(img, 0, 0, c.width, c.height); URL.revokeObjectURL(u);
        c.toBlob(function (b) { if (!b) return rej(); b.arrayBuffer().then(function (buf) { res({ mime: 'image/jpeg', data: b64(buf) }); }); }, 'image/jpeg', 0.72);
      };
      img.onerror = rej; img.src = u;
    });
  }

  // voice notes
  var rec = null, recChunks = [], recT0 = 0, recTick = null, recStream = null;
  $('micBtn').onclick = function () {
    if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)) return toast('Mic ke liye HTTPS ya localhost chahiye');
    navigator.mediaDevices.getUserMedia({ audio: true }).then(function (st) {
      recStream = st; recChunks = []; rec = new MediaRecorder(st);
      rec.ondataavailable = function (e) { if (e.data.size) recChunks.push(e.data); };
      rec.start(); recT0 = Date.now(); $('rec').hidden = false;
      recTick = setInterval(function () { var s = Math.floor((Date.now() - recT0) / 1000); $('recTime').textContent = Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2); if (s >= 120) $('recSend').click(); }, 300);
    }).catch(function () { toast('Mic ki permission nahi mili'); });
  };
  function stopRec() { clearInterval(recTick); $('rec').hidden = true; if (recStream) recStream.getTracks().forEach(function (t) { t.stop(); }); }
  $('recCancel').onclick = function () { if (rec) { rec.onstop = null; try { rec.stop(); } catch (e) {} } stopRec(); rec = null; };
  $('recSend').onclick = function () {
    if (!rec) return; var r = rec; rec = null, dur = Math.round((Date.now() - recT0) / 1000);
    r.onstop = function () { var blob = new Blob(recChunks, { type: r.mimeType || 'audio/webm' }); blob.arrayBuffer().then(function (buf) { sendPayload({ t: 'voice', mime: blob.type, dur: dur, data: b64(buf) }); }); };
    try { r.stop(); } catch (e) {} stopRec();
  };
  var dur = 0;

  // ---------- theme ----------
  $('themeBtn').onclick = function () { $('themeSheet').hidden = false; };
  $('themeClose').onclick = function () { $('themeSheet').hidden = true; };
  Array.prototype.forEach.call(document.querySelectorAll('.themes button'), function (b) {
    b.onclick = function () { document.body.dataset.theme = b.dataset.t; try { localStorage.setItem('rz-theme', b.dataset.t); } catch (e) {} $('themeSheet').hidden = true; };
  });

  // ---------- lock (blurs chat until passcode re-entered; needs no storage) ----------
  var hiddenAt = 0;
  function lock() { if (!S.key || S.locked) return; S.locked = true; $('lock').hidden = false; $('lockPass').value = ''; $('lockErr').textContent = ''; }
  function autoLockCheck() { if (hiddenAt && Date.now() - hiddenAt > 30000) lock(); hiddenAt = 0; }
  $('lockBtn').onclick = lock;
  $('lockForm').addEventListener('submit', function (e) {
    e.preventDefault();
    deriveAll($('lockPass').value, S.salt).then(function (d) {
      if (d.authHash === S.authHash) { S.locked = false; $('lock').hidden = true; if (S.sock) S.sock.emit('seen'); }
      else $('lockErr').textContent = 'Galat passcode';
    });
  });

  // ---------- calls (WebRTC, peer to peer, 1:1) ----------
  var pc = null, localStream = null, callPeer = null, pendingOffer = null, pendingIce = [];
  var ICE = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
  function otherUser() { return S.users.filter(function (u) { return u.cid !== S.clientId; })[0]; }
  function startCall(video) {
    var o = otherUser(); if (!o) return toast('Koi aur online nahi hai');
    if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)) return toast('Call ke liye HTTPS ya localhost chahiye');
    callPeer = o.sid; media(video).then(function (st) {
      localStream = st; makePc(); st.getTracks().forEach(function (t) { pc.addTrack(t, st); });
      return pc.createOffer().then(function (of) { return pc.setLocalDescription(of).then(function () { S.sock.emit('call-offer', { to: callPeer, sdp: pc.localDescription, video: video, name: S.nick }); }); });
    }).then(function () { openCallUi(video, 'Ring ho rahi hai…'); }).catch(function (e) { toast('Mic/camera nahi mila'); endCall(true); });
  }
  function media(video) { return navigator.mediaDevices.getUserMedia({ audio: true, video: video ? { facingMode: 'user' } : false }); }
  function makePc() {
    pc = new RTCPeerConnection(ICE);
    pc.onicecandidate = function (e) { if (e.candidate && callPeer) S.sock.emit('call-ice', { to: callPeer, c: e.candidate }); };
    pc.ontrack = function (e) { $('remoteV').srcObject = e.streams[0]; $('callInfo').textContent = ''; };
    pc.onconnectionstatechange = function () { if (pc && (pc.connectionState === 'failed' || pc.connectionState === 'closed')) { endCall(false); toast('Call judi nahi'); } };
  }
  function openCallUi(video, txt) { $('call').hidden = false; $('callInfo').textContent = txt; $('localV').style.display = video ? 'block' : 'none'; $('localV').srcObject = localStream; $('camBtn').style.display = video ? '' : 'none'; }
  function onOffer(d) {
    if (pc) { S.sock.emit('call-reject', { to: d.from }); return; }
    pendingOffer = d; $('incTxt').textContent = (d.name || 'Dost') + (d.video ? ' video call kar raha hai' : ' call kar raha hai'); $('incoming').hidden = false;
  }
  $('accBtn').onclick = function () {
    var d = pendingOffer; if (!d) return; $('incoming').hidden = true; callPeer = d.from;
    media(d.video).then(function (st) {
      localStream = st; makePc(); st.getTracks().forEach(function (t) { pc.addTrack(t, st); });
      return pc.setRemoteDescription(d.sdp).then(function () { return pc.createAnswer(); }).then(function (an) { return pc.setLocalDescription(an).then(function () { S.sock.emit('call-answer', { to: callPeer, sdp: pc.localDescription }); }); });
    }).then(function () { pendingIce.forEach(function (c) { pc.addIceCandidate(c).catch(function () {}); }); pendingIce = []; openCallUi(d.video, 'Judd rahe hain…'); })
      .catch(function () { toast('Mic/camera nahi mila'); S.sock.emit('call-reject', { to: d.from }); endCall(false); });
    pendingOffer = null;
  };
  $('rejBtn').onclick = function () { if (pendingOffer) S.sock.emit('call-reject', { to: pendingOffer.from }); pendingOffer = null; $('incoming').hidden = true; };
  function onAnswer(d) { if (pc) pc.setRemoteDescription(d.sdp).then(function () { pendingIce.forEach(function (c) { pc.addIceCandidate(c).catch(function () {}); }); pendingIce = []; }).catch(function () {}); }
  function onIce(d) { if (pc && pc.remoteDescription) pc.addIceCandidate(d.c).catch(function () {}); else pendingIce.push(d.c); }
  function endCall(silent) {
    if (!silent && callPeer && S.sock) S.sock.emit('call-end', { to: callPeer });
    if (pc) { try { pc.close(); } catch (e) {} pc = null; }
    if (localStream) { localStream.getTracks().forEach(function (t) { t.stop(); }); localStream = null; }
    callPeer = null; pendingOffer = null; pendingIce = []; $('call').hidden = true; $('incoming').hidden = true; $('remoteV').srcObject = null;
  }
  $('endBtn').onclick = function () { endCall(false); };
  $('muteBtn').onclick = function () { if (!localStream) return; var t = localStream.getAudioTracks()[0]; if (t) { t.enabled = !t.enabled; $('muteBtn').style.opacity = t.enabled ? 1 : .4; } };
  $('camBtn').onclick = function () { if (!localStream) return; var t = localStream.getVideoTracks()[0]; if (t) { t.enabled = !t.enabled; $('camBtn').style.opacity = t.enabled ? 1 : .4; } };
  $('voiceCallBtn').onclick = function () { startCall(false); };
  $('videoCallBtn').onclick = function () { startCall(true); };

  // ---------- load socket.io client, register service worker ----------
  var sc = document.createElement('script'); sc.src = '/socket.io/socket.io.js'; sc.onerror = function () { $('loginErr').textContent = 'Server se script nahi aayi.'; };
  document.head.appendChild(sc);
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) navigator.serviceWorker.register('/sw.js').catch(function () {});
})();
