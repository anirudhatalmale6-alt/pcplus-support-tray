const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');

// Config
const PORT = process.env.PORT || 3456;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');

// Ensure directories exist
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Database setup
const db = new Database(path.join(DATA_DIR, 'chat.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    username TEXT,
    ip_address TEXT,
    os_info TEXT,
    agent_id TEXT,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    online INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    sender TEXT NOT NULL CHECK(sender IN ('client', 'support')),
    message TEXT,
    attachment TEXT,
    attachment_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    read INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id)
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'resolved', 'closed')),
    priority TEXT DEFAULT 'normal' CHECK(priority IN ('low', 'normal', 'high', 'critical')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (client_id) REFERENCES clients(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_client ON messages(client_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_tickets_client ON tickets(client_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
`);

// Prepared statements
const stmts = {
  upsertClient: db.prepare(`
    INSERT INTO clients (id, hostname, username, ip_address, os_info, agent_id, last_seen, online)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'), 1)
    ON CONFLICT(id) DO UPDATE SET
      hostname = excluded.hostname,
      username = excluded.username,
      ip_address = excluded.ip_address,
      os_info = excluded.os_info,
      agent_id = excluded.agent_id,
      last_seen = datetime('now'),
      online = 1
  `),
  setOffline: db.prepare(`UPDATE clients SET online = 0 WHERE id = ?`),
  insertMessage: db.prepare(`
    INSERT INTO messages (client_id, sender, message, attachment, attachment_name)
    VALUES (?, ?, ?, ?, ?)
  `),
  getMessages: db.prepare(`
    SELECT * FROM messages WHERE client_id = ? ORDER BY created_at DESC LIMIT ?
  `),
  getClients: db.prepare(`SELECT * FROM clients ORDER BY last_seen DESC`),
  getClient: db.prepare(`SELECT * FROM clients WHERE id = ?`),
  insertTicket: db.prepare(`
    INSERT INTO tickets (client_id, subject, description, priority)
    VALUES (?, ?, ?, ?)
  `),
  getTickets: db.prepare(`SELECT * FROM tickets ORDER BY created_at DESC`),
  getTicketsByClient: db.prepare(`SELECT * FROM tickets WHERE client_id = ? ORDER BY created_at DESC`),
  updateTicketStatus: db.prepare(`UPDATE tickets SET status = ?, updated_at = datetime('now') WHERE id = ?`),
  markRead: db.prepare(`UPDATE messages SET read = 1 WHERE client_id = ? AND sender = 'client'`),
  getUnreadCount: db.prepare(`SELECT client_id, COUNT(*) as count FROM messages WHERE sender = 'client' AND read = 0 GROUP BY client_id`),
};

// Express app
const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/admin', express.static(path.join(__dirname, 'public')));

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${uuidv4().slice(0, 8)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|bmp|webp|pdf|txt|log|zip)$/i;
    cb(null, allowed.test(path.extname(file.originalname)));
  }
});

// HTTP server
const server = http.createServer(app);

// WebSocket server
const wss = new WebSocket.Server({ server, path: '/ws' });

// Track connected clients and admin
const clientSockets = new Map(); // clientId -> ws
const adminSockets = new Set();

wss.on('connection', (ws, req) => {
  let clientId = null;
  let isAdmin = false;

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);

      switch (msg.type) {
        case 'auth_client': {
          clientId = msg.clientId || uuidv4();
          clientSockets.set(clientId, ws);
          stmts.upsertClient.run(
            clientId,
            msg.hostname || '',
            msg.username || '',
            msg.ip || '',
            msg.os || '',
            msg.agentId || ''
          );
          ws.send(JSON.stringify({ type: 'auth_ok', clientId }));

          // Notify admin panels
          broadcastToAdmin({ type: 'client_online', clientId, hostname: msg.hostname });

          // Send recent message history
          const history = stmts.getMessages.all(clientId, 50).reverse();
          ws.send(JSON.stringify({ type: 'history', messages: history }));
          break;
        }

        case 'auth_admin': {
          // Simple token-based admin auth
          if (msg.token === process.env.ADMIN_TOKEN || msg.token === 'pcplus2026') {
            isAdmin = true;
            adminSockets.add(ws);
            ws.send(JSON.stringify({ type: 'auth_ok', role: 'admin' }));

            // Send client list with unread counts
            const clients = stmts.getClients.all();
            const unread = stmts.getUnreadCount.all();
            const unreadMap = {};
            unread.forEach(u => { unreadMap[u.client_id] = u.count; });
            ws.send(JSON.stringify({ type: 'client_list', clients, unreadCounts: unreadMap }));
          } else {
            ws.send(JSON.stringify({ type: 'auth_fail', message: 'Invalid token' }));
          }
          break;
        }

        case 'message': {
          if (isAdmin && msg.clientId) {
            // Admin sending to a client
            const result = stmts.insertMessage.run(msg.clientId, 'support', msg.text, msg.attachment || null, msg.attachmentName || null);
            const savedMsg = { id: result.lastInsertRowid, client_id: msg.clientId, sender: 'support', message: msg.text, attachment: msg.attachment, attachment_name: msg.attachmentName, created_at: new Date().toISOString() };

            // Send to client if online
            const clientWs = clientSockets.get(msg.clientId);
            if (clientWs && clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({ type: 'message', ...savedMsg }));
            }

            // Echo back to all admins
            broadcastToAdmin({ type: 'message', ...savedMsg });
          } else if (clientId) {
            // Client sending message
            const result = stmts.insertMessage.run(clientId, 'client', msg.text, msg.attachment || null, msg.attachmentName || null);
            const savedMsg = { id: result.lastInsertRowid, client_id: clientId, sender: 'client', message: msg.text, attachment: msg.attachment, attachment_name: msg.attachmentName, created_at: new Date().toISOString() };

            // Send to all admin panels
            broadcastToAdmin({ type: 'message', ...savedMsg });

            // Echo back to client
            ws.send(JSON.stringify({ type: 'message', ...savedMsg }));
          }
          break;
        }

        case 'load_chat': {
          if (isAdmin && msg.clientId) {
            const messages = stmts.getMessages.all(msg.clientId, 100).reverse();
            const client = stmts.getClient.get(msg.clientId);
            stmts.markRead.run(msg.clientId);
            ws.send(JSON.stringify({ type: 'chat_history', clientId: msg.clientId, messages, client }));
          }
          break;
        }

        case 'mark_read': {
          if (isAdmin && msg.clientId) {
            stmts.markRead.run(msg.clientId);
          }
          break;
        }
      }
    } catch (err) {
      console.error('WS message error:', err);
    }
  });

  ws.on('close', () => {
    if (clientId) {
      clientSockets.delete(clientId);
      stmts.setOffline.run(clientId);
      broadcastToAdmin({ type: 'client_offline', clientId });
    }
    if (isAdmin) {
      adminSockets.delete(ws);
    }
  });
});

function broadcastToAdmin(data) {
  const json = JSON.stringify(data);
  adminSockets.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(json);
  });
}

// REST API endpoints

// Upload file
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    filename: req.file.filename,
    originalName: req.file.originalname,
    size: req.file.size,
    url: `/uploads/${req.file.filename}`
  });
});

// Get all clients
app.get('/api/clients', (req, res) => {
  const clients = stmts.getClients.all();
  res.json(clients);
});

// Create ticket
app.post('/api/tickets', (req, res) => {
  const { clientId, subject, description, priority } = req.body;
  if (!subject) return res.status(400).json({ error: 'Subject required' });
  const result = stmts.insertTicket.run(clientId || 'unknown', subject, description || '', priority || 'normal');
  res.json({ id: result.lastInsertRowid, message: 'Ticket created' });
});

// Get tickets
app.get('/api/tickets', (req, res) => {
  const tickets = stmts.getTickets.all();
  res.json(tickets);
});

// Update ticket status
app.patch('/api/tickets/:id', (req, res) => {
  const { status } = req.body;
  stmts.updateTicketStatus.run(status, req.params.id);
  res.json({ message: 'Updated' });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    clients: clientSockets.size,
    admins: adminSockets.size,
    uptime: process.uptime()
  });
});

// Serve admin panel
app.get('/', (req, res) => {
  res.redirect('/admin');
});

server.listen(PORT, () => {
  console.log(`PC Plus Support Chat Server running on port ${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
  console.log(`WebSocket: ws://localhost:${PORT}/ws`);
});

process.on('SIGINT', () => {
  db.close();
  process.exit(0);
});
