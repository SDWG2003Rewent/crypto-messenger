// ═══════════════════════════════════════════
//  CRYPTO MESSENGER v4 — FIXED FILE TRANSFER
//  Ограничение: 100MB, правильный чанкинг
// ═══════════════════════════════════════════

const API_URL = window.location.origin;
let socket = null;
let currentUser = null;
let identityPrivateKey = null;
let identityPublicKey = null;
let identityPublicKeyJwk = null;
let currentRoomId = null;
let currentPartnerId = null;
let userPublicKeys = {};
let onlineUsersSet = new Set();
let dmRooms = {};

// ─── Хранилище для сборки файлов ───
const fileReceiverCache = new Map(); // fileId -> { metadata, chunks, received, total }

// ─── IndexedDB ───
const DB_NAME = 'CryptoMessenger';
const DB_VERSION = 2;
let db = null;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => { db = req.result; resolve(db); };
    req.onupgradeneeded = (e) => {
      const d = e.target.result;
      if (!d.objectStoreNames.contains('keys')) {
        d.createObjectStore('keys', { keyPath: 'id' });
      }
      if (!d.objectStoreNames.contains('files')) {
        d.createObjectStore('files', { keyPath: 'id' });
      }
    };
  });
}

async function saveToStore(storeName, data) {
  const tx = db.transaction(storeName, 'readwrite');
  const store = tx.objectStore(storeName);
  store.put(data);
  return new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
}

async function getFromStore(storeName, key) {
  const tx = db.transaction(storeName, 'readonly');
  const store = tx.objectStore(storeName);
  const req = store.get(key);
  return new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
}

// ─── Web Crypto ───

async function generateIdentityKeys() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits', 'deriveKey']
  );
  identityPrivateKey = keyPair.privateKey;
  identityPublicKey = keyPair.publicKey;
  identityPublicKeyJwk = await crypto.subtle.exportKey('jwk', identityPublicKey);
  
  const privateJwk = await crypto.subtle.exportKey('jwk', identityPrivateKey);
  await saveToStore('keys', { id: 'identityPrivateJwk', jwk: privateJwk });
  await saveToStore('keys', { id: 'identityPublicJwk', jwk: identityPublicKeyJwk });
}

async function loadIdentityKeys() {
  const privJwk = await getFromStore('keys', 'identityPrivateJwk');
  const pubJwk = await getFromStore('keys', 'identityPublicJwk');
  if (!privJwk || !pubJwk) return false;
  
  identityPrivateKey = await crypto.subtle.importKey('jwk', privJwk.jwk,
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  identityPublicKeyJwk = pubJwk.jwk;
  identityPublicKey = await crypto.subtle.importKey('jwk', identityPublicKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  return true;
}

async function importPublicKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

// ─── Шифрование ───

async function encryptForPublicKey(publicKey, data) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey }, ephemeral.privateKey, 256
  );
  const aesKey = await crypto.subtle.importKey('raw', sharedBits, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  let dataBuffer;
  if (typeof data === 'string') {
    dataBuffer = new TextEncoder().encode(data);
  } else if (data instanceof ArrayBuffer) {
    dataBuffer = new Uint8Array(data);
  } else if (data instanceof Uint8Array) {
    dataBuffer = data;
  } else {
    dataBuffer = new TextEncoder().encode(JSON.stringify(data));
  }
  
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, dataBuffer);
  const ephemeralJwk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);
  return { 
    ephemeralPublicKey: ephemeralJwk, 
    iv: Array.from(iv), 
    ciphertext: Array.from(new Uint8Array(ciphertext)) 
  };
}

async function decryptWithPrivateKey(privateKey, payload) {
  const ephemeralPub = await crypto.subtle.importKey('jwk', payload.ephemeralPublicKey,
    { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: ephemeralPub }, privateKey, 256
  );
  const aesKey = await crypto.subtle.importKey('raw', sharedBits, { name: 'AES-GCM' }, false, ['decrypt']);
  const iv = new Uint8Array(payload.iv);
  const ciphertext = new Uint8Array(payload.ciphertext);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  return new Uint8Array(decrypted);
}

// ─── НОВАЯ СИСТЕМА ОТПРАВКИ ФАЙЛОВ ───

const CHUNK_SIZE = 256 * 1024; // 256KB на чанк - оптимально для сети

async function sendFileWithChunks(file) {
  if (!currentRoomId || !currentPartnerId) {
    showSystemMessage('No active chat');
    return;
  }
  
  const pubKey = userPublicKeys[currentPartnerId];
  if (!pubKey) {
    showSystemMessage('Peer public key not available');
    return;
  }

  if (file.size > 100 * 1024 * 1024) {
    showSystemMessage('❌ File too large (max 100MB)');
    return;
  }

  const fileId = Date.now() + '_' + file.name;
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  
  showSystemMessage(`📤 Sending ${file.name} (${(file.size/1024/1024).toFixed(1)}MB, ${totalChunks} chunks)...`);

  try {
    // 1. Отправляем метаданные
    const metadata = {
      fileId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type || 'application/octet-stream',
      totalChunks
    };
    
    const metaEncrypted = await encryptForPublicKey(pubKey, JSON.stringify(metadata));
    socket.emit('send-message', {
      roomId: currentRoomId,
      encryptedPayload: JSON.stringify(metaEncrypted),
      ephemeralPublicKey: JSON.stringify(metaEncrypted.ephemeralPublicKey),
      isMedia: true,
      mediaType: 'file_metadata',
      fileId: fileId
    });

    // 2. Читаем и отправляем чанки
    const reader = new FileReader();
    let chunkIndex = 0;
    
    const readChunk = (start) => {
      const end = Math.min(start + CHUNK_SIZE, file.size);
      const blob = file.slice(start, end);
      reader.readAsArrayBuffer(blob);
    };

    reader.onload = async (e) => {
      const chunkData = new Uint8Array(e.target.result);
      const encrypted = await encryptForPublicKey(pubKey, chunkData);
      
      socket.emit('send-message', {
        roomId: currentRoomId,
        encryptedPayload: JSON.stringify(encrypted),
        ephemeralPublicKey: JSON.stringify(encrypted.ephemeralPublicKey),
        isMedia: true,
        mediaType: 'file_chunk',
        fileId: fileId,
        chunkIndex: chunkIndex,
        totalChunks: totalChunks,
        isLastChunk: chunkIndex === totalChunks - 1
      });

      chunkIndex++;
      
      // Обновляем прогресс
      const progress = Math.round((chunkIndex / totalChunks) * 100);
      if (chunkIndex % 5 === 0 || chunkIndex === totalChunks) {
        showSystemMessage(`📤 Sending ${file.name}: ${progress}%`);
      }

      // Читаем следующий чанк
      if (chunkIndex < totalChunks) {
        readChunk(chunkIndex * CHUNK_SIZE);
      } else {
        showSystemMessage(`✅ ${file.name} sent successfully!`);
      }
    };

    reader.onerror = () => {
      showSystemMessage('❌ Error reading file');
    };

    readChunk(0);

  } catch (e) {
    console.error('File send failed:', e);
    showSystemMessage('❌ File send failed: ' + e.message);
  }
}

// ─── ОБРАБОТКА ПОЛУЧЕННЫХ ФАЙЛОВ ───

async function handleFileMetadata(payload, msg) {
  try {
    const decrypted = await decryptWithPrivateKey(identityPrivateKey, payload);
    const metadata = JSON.parse(new TextDecoder().decode(decrypted));
    
    const fileId = metadata.fileId || msg.fileId || Date.now() + '_file';
    
    // Сохраняем в кэш
    fileReceiverCache.set(fileId, {
      metadata: metadata,
      chunks: new Map(),
      received: 0,
      total: metadata.totalChunks || 0,
      lastUpdate: Date.now()
    });

    // Показываем сообщение о начале загрузки
    showSystemMessage(`📥 Receiving ${metadata.fileName} (${(metadata.fileSize/1024/1024).toFixed(1)}MB)...`);
    
    // Добавляем временное сообщение в чат
    const container = document.getElementById('messages');
    const div = document.createElement('div');
    div.className = 'message other';
    div.id = 'file_' + fileId;
    div.innerHTML = `
      <div class="sender">${esc(msg.senderLogin)}</div>
      <div class="text">📄 ${esc(metadata.fileName)} (${(metadata.fileSize/1024/1024).toFixed(1)}MB)</div>
      <div class="meta" id="progress_${fileId}">Downloading: 0%</div>
    `;
    container.appendChild(div);
    scrollBottom();
    
  } catch (e) {
    console.error('Metadata decrypt error:', e);
  }
}

async function handleFileChunk(payload, msg) {
  try {
    const fileId = msg.fileId;
    if (!fileId) {
      console.warn('No fileId in chunk');
      return;
    }

    const cache = fileReceiverCache.get(fileId);
    if (!cache) {
      console.warn('No cache for fileId:', fileId);
      return;
    }

    const decrypted = await decryptWithPrivateKey(identityPrivateKey, payload);
    const chunkIndex = msg.chunkIndex || 0;
    
    cache.chunks.set(chunkIndex, decrypted);
    cache.received++;
    
    // Обновляем прогресс
    const progress = Math.round((cache.received / cache.total) * 100);
    const progressEl = document.getElementById('progress_' + fileId);
    if (progressEl) {
      progressEl.textContent = `Downloading: ${progress}%`;
    }

    // Если все чанки получены - собираем файл
    if (cache.received === cache.total) {
      await assembleFile(fileId);
    }
    
  } catch (e) {
    console.error('Chunk decrypt error:', e);
  }
}

async function assembleFile(fileId) {
  const cache = fileReceiverCache.get(fileId);
  if (!cache) return;

  try {
    const { metadata, chunks, total } = cache;
    
    // Проверяем, что все чанки на месте
    for (let i = 0; i < total; i++) {
      if (!chunks.has(i)) {
        console.warn('Missing chunk:', i);
        return;
      }
    }

    // Собираем файл
    const chunksArray = [];
    let totalSize = 0;
    for (let i = 0; i < total; i++) {
      const chunk = chunks.get(i);
      chunksArray.push(chunk);
      totalSize += chunk.length;
    }

    // Объединяем
    const fullData = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of chunksArray) {
      fullData.set(chunk, offset);
      offset += chunk.length;
    }

    // Создаём URL для скачивания
    const blob = new Blob([fullData], { type: metadata.fileType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    
    // Обновляем сообщение в чате
    const msgEl = document.getElementById('file_' + fileId);
    if (msgEl) {
      const fileName = metadata.fileName || 'file';
      const fileSize = (metadata.fileSize / 1024 / 1024).toFixed(1);
      msgEl.innerHTML = `
        <div class="sender">${msgEl.querySelector('.sender')?.textContent || ''}</div>
        <div class="text">
          📄 <a href="${url}" download="${esc(fileName)}" style="color: var(--accent-light); cursor: pointer;">
            ${esc(fileName)}
          </a> (${fileSize}MB) ✅
          <br><small style="color: var(--text-dim);">Click to download</small>
        </div>
        <div class="meta">${new Date().toLocaleTimeString()}</div>
      `;
    }

    showSystemMessage(`✅ File ${metadata.fileName} received!`);

    // Очищаем кэш через 5 минут
    setTimeout(() => {
      fileReceiverCache.delete(fileId);
    }, 5 * 60 * 1000);

  } catch (e) {
    console.error('File assembly error:', e);
    showSystemMessage('❌ Error assembling file: ' + e.message);
  }
}

// ─── API ───

async function api(path, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (currentUser?.token) opts.headers['Authorization'] = `Bearer ${currentUser.token}`;
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${API_URL}/api${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ─── Auth ───

async function register() {
  const login = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;
  const errorEl = document.getElementById('reg-error');
  if (!login || !password) { errorEl.textContent = 'Enter username and password'; return; }

  try {
    await openDB();
    await generateIdentityKeys();

    const res = await api('/register', 'POST', {
      login, password,
      publicKey: identityPublicKeyJwk
    });

    currentUser = { ...res.user, token: res.token };
    await saveToStore('keys', { id: 'currentUser', user: currentUser });

    await setupAfterAuth();
    showMain();
  } catch (e) {
    errorEl.textContent = e.message;
  }
}

async function login() {
  const login = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errorEl = document.getElementById('login-error');
  if (!login || !password) { errorEl.textContent = 'Enter username and password'; return; }

  try {
    await openDB();
    const res = await api('/login', 'POST', { login, password });
    currentUser = { ...res.user, token: res.token };
    await saveToStore('keys', { id: 'currentUser', user: currentUser });

    const hasKeys = await loadIdentityKeys();
    if (!hasKeys) {
      await generateIdentityKeys();
      await api('/update-key', 'POST', { publicKey: identityPublicKeyJwk });
    }

    await setupAfterAuth();
    showMain();
  } catch (e) {
    errorEl.textContent = e.message;
  }
}

async function setupAfterAuth() {
  await loadUsers();
  await loadConversations();
  connectSocket();
}

async function loadUsers() {
  try {
    const users = await api('/users');
    const list = document.getElementById('user-list');
    list.innerHTML = '';
    for (const u of users) {
      try { userPublicKeys[u.id] = await importPublicKey(u.publicKey); }
      catch (e) { console.warn('Bad pubkey for', u.login); }
      const div = document.createElement('div');
      div.className = 'user-item' + (onlineUsersSet.has(u.id) ? ' online' : '');
      div.dataset.userId = u.id;
      div.innerHTML = `<div class="status"></div><span class="name">${esc(u.login)}</span>`;
      div.onclick = () => startDM(u.id, u.login);
      list.appendChild(div);
    }
  } catch (e) { console.error('Load users failed:', e); }
}

async function loadConversations() {
  try {
    const rooms = await api('/rooms');
    const list = document.getElementById('dm-list');
    list.innerHTML = '';
    for (const room of rooms) {
      try {
        const members = await api(`/rooms/${room.id}/members`);
        if (members && members.length > 0) {
          const partner = members[0];
          dmRooms[partner.id] = room.id;
          const div = document.createElement('div');
          div.className = 'dm-item';
          div.dataset.room = room.id;
          div.dataset.partner = partner.id;
          div.innerHTML = `<span class="dm-prefix">◈</span><span class="name">${esc(partner.login)}</span>`;
          div.onclick = () => openDM(room.id, partner.id, partner.login);
          list.appendChild(div);
        }
      } catch (e) {
        console.warn('Failed to load members for room', room.id);
      }
    }
  } catch (e) { console.error('Load conversations failed:', e); }
}

function esc(t) {
  const d = document.createElement('div');
  d.textContent = t;
  return d.innerHTML;
}

// ─── Socket ───

function connectSocket() {
  if (socket) socket.disconnect();
  socket = io({ auth: { token: currentUser.token } });

  socket.on('connect', () => {
    console.log('Socket connected');
    if (currentRoomId) socket.emit('join-room', currentRoomId);
  });

  socket.on('online-users', (users) => {
    onlineUsersSet = new Set(users);
    document.querySelectorAll('.user-item').forEach(el => {
      el.classList.toggle('online', onlineUsersSet.has(el.dataset.userId));
    });
  });

  socket.on('new-message', async (msg) => {
    if (msg.roomId !== currentRoomId) return;
    
    // Обработка файлов
    if (msg.mediaType === 'file_metadata') {
      const payload = JSON.parse(msg.encryptedPayload);
      await handleFileMetadata(payload, msg);
      return;
    }
    
    if (msg.mediaType === 'file_chunk') {
      const payload = JSON.parse(msg.encryptedPayload);
      await handleFileChunk(payload, msg);
      return;
    }
    
    // Обычное сообщение
    await renderMessage(msg);
    scrollBottom();
  });

  socket.on('user-online', (u) => {
    onlineUsersSet.add(u.userId);
    updateUserStatus(u.userId, true);
  });

  socket.on('user-offline', (u) => {
    onlineUsersSet.delete(u.userId);
    updateUserStatus(u.userId, false);
  });
}

function updateUserStatus(userId, online) {
  const el = document.querySelector(`.user-item[data-user-id="${userId}"]`);
  if (el) el.classList.toggle('online', online);
}

// ─── DM ───

async function startDM(userId, login) {
  try {
    let roomId = dmRooms[userId];
    if (!roomId) {
      const res = await api('/dm', 'POST', { targetUserId: userId });
      roomId = res.roomId;
      dmRooms[userId] = roomId;
      const list = document.getElementById('dm-list');
      const div = document.createElement('div');
      div.className = 'dm-item';
      div.dataset.room = roomId;
      div.dataset.partner = userId;
      div.innerHTML = `<span class="dm-prefix">◈</span><span class="name">${esc(login)}</span>`;
      div.onclick = () => openDM(roomId, userId, login);
      list.appendChild(div);
    }
    openDM(roomId, userId, login);
  } catch (e) {
    console.error('Start DM failed:', e);
    showSystemMessage('Failed to start conversation');
  }
}

function openDM(roomId, partnerId, login) {
  currentRoomId = roomId;
  currentPartnerId = partnerId;
  document.getElementById('chat-title').textContent = login;

  document.querySelectorAll('.dm-item').forEach(r => r.classList.remove('active'));
  const el = document.querySelector(`.dm-item[data-room="${roomId}"]`);
  if (el) el.classList.add('active');

  if (socket) socket.emit('join-room', roomId);
  loadMessages(roomId);
}

// ─── Messaging ───

async function sendMessage() {
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text || !currentRoomId || !currentPartnerId) return;

  const pubKey = userPublicKeys[currentPartnerId];
  if (!pubKey) {
    showSystemMessage('Peer public key not available');
    return;
  }

  try {
    const encrypted = await encryptForPublicKey(pubKey, text);
    socket.emit('send-message', {
      roomId: currentRoomId,
      encryptedPayload: JSON.stringify(encrypted),
      ephemeralPublicKey: JSON.stringify(encrypted.ephemeralPublicKey)
    });
    input.value = '';
    renderLocalMessage(text, false);
  } catch (e) {
    console.error('Send failed:', e);
    showSystemMessage('Send failed');
  }
}

async function renderMessage(msg) {
  const container = document.getElementById('messages');
  const div = document.createElement('div');
  const isOwn = msg.senderId === currentUser.id;
  div.className = 'message ' + (isOwn ? 'own' : 'other');

  let text = '[Encrypted]';
  let isMedia = msg.isMedia || msg.is_media;
  let mediaType = msg.mediaType || msg.media_type;
  const time = new Date(msg.timestamp).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  const sender = !isOwn ? `<div class="sender">${esc(msg.senderLogin)}</div>` : '';

  try {
    const payload = JSON.parse(msg.encryptedPayload);
    const decryptedData = await decryptWithPrivateKey(identityPrivateKey, payload);
    text = new TextDecoder().decode(decryptedData);
    
    if (isMedia && (text.startsWith('data:') || mediaType?.startsWith('image/'))) {
      div.innerHTML = `${sender}<img src="${text}" class="media-img" onload="scrollBottom()"><div class="meta">${time}</div>`;
    } else {
      div.innerHTML = `${sender}<div class="text">${esc(text)}</div><div class="meta">${time}</div>`;
    }
    
  } catch (e) {
    console.warn('Decrypt error:', e);
    div.innerHTML = `${sender}<div class="text">🔒 Encrypted message</div><div class="meta">${time}</div>`;
  }
  
  container.appendChild(div);
}

function renderLocalMessage(text, isMedia) {
  const container = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'message own';
  const time = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  if (isMedia && text.startsWith('data:')) {
    div.innerHTML = `<img src="${text}" class="media-img" onload="scrollBottom()"><div class="meta">${time} [SENT]</div>`;
  } else {
    div.innerHTML = `<div class="text">${esc(text)}</div><div class="meta">${time} [SENT]</div>`;
  }
  container.appendChild(div);
  scrollBottom();
}

async function loadMessages(roomId) {
  const container = document.getElementById('messages');
  container.innerHTML = '<div class="system-msg">Loading messages...</div>';
  try {
    const msgs = await api(`/messages/${roomId}`);
    container.innerHTML = '';
    for (const msg of msgs) await renderMessage(msg);
    scrollBottom();
  } catch (e) {
    container.innerHTML = '<div class="error-msg">Failed to load messages</div>';
  }
}

function showSystemMessage(text) {
  const container = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'system-msg';
  div.textContent = text;
  container.appendChild(div);
  scrollBottom();
}

function scrollBottom() {
  const c = document.getElementById('messages');
  setTimeout(() => { c.scrollTop = c.scrollHeight; }, 50);
}

// ─── UI ───

function showMain() {
  document.getElementById('auth-screen').classList.remove('active');
  document.getElementById('main-screen').classList.add('active');
  document.getElementById('current-user').textContent = currentUser.login;
}

function showAuth() {
  document.getElementById('main-screen').classList.remove('active');
  document.getElementById('auth-screen').classList.add('active');
}

// Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab + '-form').classList.add('active');
  });
});

document.getElementById('btn-login').addEventListener('click', login);
document.getElementById('btn-register').addEventListener('click', register);
document.getElementById('btn-logout').addEventListener('click', () => {
  if (socket) socket.disconnect();
  currentUser = null;
  identityPrivateKey = null;
  dmRooms = {};
  showAuth();
});

document.getElementById('btn-send').addEventListener('click', sendMessage);
document.getElementById('message-input').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') sendMessage();
});

// ─── Файлы ───

document.getElementById('btn-attach').addEventListener('click', () => {
  document.getElementById('file-input').click();
});

document.getElementById('file-input').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file || !currentRoomId) {
    e.target.value = '';
    return;
  }
  
  // Если файл меньше 5MB - отправляем как base64 (для изображений)
  if (file.size < 5 * 1024 * 1024 && file.type.startsWith('image/')) {
    const reader = new FileReader();
    reader.onload = (ev) => {
      sendImageMessage(ev.target.result, file.type);
      e.target.value = '';
    };
    reader.readAsDataURL(file);
  } else {
    // Большие файлы или не-изображения - через чанкинг
    await sendFileWithChunks(file);
    e.target.value = '';
  }
});

async function sendImageMessage(base64Data, mediaType) {
  if (!currentRoomId || !currentPartnerId) return;
  const pubKey = userPublicKeys[currentPartnerId];
  if (!pubKey) { showSystemMessage('Peer public key not available'); return; }

  try {
    const encrypted = await encryptForPublicKey(pubKey, base64Data);
    socket.emit('send-message', {
      roomId: currentRoomId,
      encryptedPayload: JSON.stringify(encrypted),
      ephemeralPublicKey: JSON.stringify(encrypted.ephemeralPublicKey),
      isMedia: true, 
      mediaType
    });
    renderLocalMessage(base64Data, true);
  } catch (e) {
    console.error('Image send failed:', e);
    showSystemMessage('Image send failed');
  }
}

// Mobile menu
document.querySelector('.chat-header').addEventListener('click', (e) => {
  if (window.innerWidth <= 768) {
    document.querySelector('.sidebar').classList.toggle('open');
  }
});

// Service Worker
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(console.error);
}

// Auto-login
(async () => {
  try {
    await openDB();
    const saved = await getFromStore('keys', 'currentUser');
    if (saved?.user) {
      currentUser = saved.user;
      const hasKeys = await loadIdentityKeys();
      if (hasKeys) {
        await setupAfterAuth();
        showMain();
      }
    }
  } catch (e) {
    console.log('Auto-login failed:', e.message);
  }
})();

// Enter в формах
document.addEventListener('keypress', (e) => {
  if (e.target.closest('#login-form') && e.key === 'Enter') login();
  if (e.target.closest('#register-form') && e.key === 'Enter') register();
});