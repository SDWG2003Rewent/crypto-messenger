const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'crypto-messenger-secret-change-in-production';
const PORT = process.env.PORT || 8080;

if (!process.env.JWT_SECRET) {
  console.warn('[WARN] JWT_SECRET не задан в переменных окружения! Используется небезопасное значение по умолчанию. Задай JWT_SECRET в настройках Railway (Variables).');
}

// Для Railway - используем порт из окружения
const port = PORT;

// Railway работает за прокси - нужно для корректного определения протокола/IP
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, '../public')));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
  maxHttpBufferSize: 100 * 1024 * 1024
});

// База данных SQLite
// На Railway файловая система эфемерна: без подключённого Volume база будет
// сбрасываться при каждом редеплое/рестарте. Чтобы данные сохранялись,
// подключи Volume в Railway и укажи переменную окружения DB_PATH,
// например: DB_PATH=/data/database.sqlite
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');
if (!process.env.DB_PATH) {
  console.warn('[WARN] DB_PATH не задан — база хранится во временной файловой системе контейнера и будет стёрта при редеплое. Подключи Railway Volume и задай DB_PATH, если нужно постоянное хранение.');
}
const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('dm')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS room_members (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (room_id, user_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    encrypted_payload TEXT NOT NULL,
    ephemeral_public_key TEXT,
    is_media INTEGER DEFAULT 0,
    media_type TEXT,
    file_id TEXT,
    chunk_index INTEGER,
    total_chunks INTEGER,
    is_last_chunk INTEGER DEFAULT 0,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id)`);
});

console.log('[DB] ✅ Database initialized');

function generateToken(user) {
  return jwt.sign({ id: user.id, login: user.login }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── API ───

app.post('/api/register', (req, res) => {
  const { login, password, publicKey } = req.body;
  if (!login || !password || !publicKey) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users (id, login, password_hash, public_key) VALUES (?, ?, ?, ?)`,
    [id, login, hash, JSON.stringify(publicKey)],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(409).json({ error: 'Login taken' });
        }
        return res.status(500).json({ error: err.message });
      }
      const token = generateToken({ id, login });
      res.json({ token, user: { id, login, publicKey } });
    }
  );
});

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  db.get(`SELECT * FROM users WHERE login = ?`, [login], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = generateToken(user);
    res.json({ token, user: { id: user.id, login: user.login, publicKey: JSON.parse(user.public_key) } });
  });
});

app.post('/api/update-key', authMiddleware, (req, res) => {
  db.run(
    `UPDATE users SET public_key = ? WHERE id = ?`,
    [JSON.stringify(req.body.publicKey), req.user.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

app.get('/api/users', authMiddleware, (req, res) => {
  db.all(
    `SELECT id, login, public_key as publicKey FROM users WHERE id != ?`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows.map(r => ({ ...r, publicKey: JSON.parse(r.publicKey) })));
    }
  );
});

app.get('/api/rooms', authMiddleware, (req, res) => {
  db.all(
    `SELECT r.id, r.name, r.type FROM rooms r
     JOIN room_members rm ON r.id = rm.room_id WHERE rm.user_id = ?`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/api/rooms/:roomId/members', authMiddleware, (req, res) => {
  db.all(
    `SELECT u.id, u.login FROM room_members rm
     JOIN users u ON rm.user_id = u.id WHERE rm.room_id = ? AND u.id != ?`,
    [req.params.roomId, req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/api/messages/:roomId', authMiddleware, (req, res) => {
  const limit = parseInt(req.query.limit) || 500;
  db.all(
    `SELECT m.id, m.room_id as roomId, m.sender_id as senderId, u.login as senderLogin,
     m.encrypted_payload as encryptedPayload, m.ephemeral_public_key as ephemeralPublicKey,
     m.is_media as isMedia, m.media_type as mediaType,
     m.file_id as fileId, m.chunk_index as chunkIndex,
     m.total_chunks as totalChunks, m.is_last_chunk as isLastChunk,
     m.timestamp
     FROM messages m
     JOIN users u ON m.sender_id = u.id
     WHERE m.room_id = ?
     ORDER BY m.timestamp ASC LIMIT ?`,
    [req.params.roomId, limit],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.post('/api/dm', authMiddleware, (req, res) => {
  const { targetUserId } = req.body;
  const userId = req.user.id;

  db.all(
    `SELECT room_id FROM room_members WHERE user_id IN (?, ?) GROUP BY room_id HAVING COUNT(*) = 2`,
    [userId, targetUserId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      if (rows.length > 0) return res.json({ roomId: rows[0].room_id });

      const roomId = uuidv4();
      db.run(`INSERT INTO rooms (id, name, type) VALUES (?, ?, ?)`, [roomId, 'DM', 'dm'], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        db.run(
          `INSERT INTO room_members (room_id, user_id) VALUES (?, ?), (?, ?)`,
          [roomId, userId, roomId, targetUserId],
          (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ roomId });
          }
        );
      });
    }
  );
});

// ─── Socket.IO ───
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log('[SOCKET]', socket.user.login, 'connected');
  onlineUsers.set(socket.user.id, socket.id);

  const allOnline = Array.from(onlineUsers.keys());
  socket.emit('online-users', allOnline);
  socket.broadcast.emit('user-online', { userId: socket.user.id, login: socket.user.login });

  socket.on('join-room', (roomId) => {
    socket.join(roomId);
  });

  socket.on('send-message', (data) => {
    const { roomId, encryptedPayload, ephemeralPublicKey, isMedia, mediaType, fileId, chunkIndex, totalChunks, isLastChunk } = data;
    const msgId = uuidv4();

    db.run(
      `INSERT INTO messages (
        id, room_id, sender_id, encrypted_payload, ephemeral_public_key,
        is_media, media_type, file_id, chunk_index, total_chunks, is_last_chunk
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        msgId, roomId, socket.user.id, encryptedPayload, ephemeralPublicKey || null,
        isMedia ? 1 : 0, mediaType || null,
        fileId || null, chunkIndex || null, totalChunks || null, isLastChunk ? 1 : 0
      ],
      (err) => {
        if (err) {
          console.error('[DB] Save error:', err);
          socket.emit('error', { message: 'Failed to save' });
          return;
        }
        io.to(roomId).emit('new-message', {
          id: msgId,
          roomId,
          senderId: socket.user.id,
          senderLogin: socket.user.login,
          encryptedPayload,
          ephemeralPublicKey: ephemeralPublicKey || null,
          isMedia: isMedia || false,
          mediaType: mediaType || null,
          fileId: fileId || null,
          chunkIndex: chunkIndex || null,
          totalChunks: totalChunks || null,
          isLastChunk: isLastChunk || false,
          timestamp: new Date().toISOString()
        });
      }
    );
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.user.id);
    socket.broadcast.emit('user-offline', { userId: socket.user.id });
  });
});

// ─── Запуск ───
server.listen(port, '0.0.0.0', () => {
  console.log(`[SERVER] Running on port ${port}`);
  const publicUrl = process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${port}`;
  console.log(`[SERVER] URL: ${publicUrl}`);
});