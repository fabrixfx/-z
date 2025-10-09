const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const db = new sqlite3.Database('chat.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY, 
      from_user TEXT, 
      to_user TEXT, 
      message TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.use(bodyParser.json());
app.use(express.static('public'));

// Регистрация
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error: 'Логин и пароль обязательны' });
  const hashed = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashed], function(err){
    if(err) return res.status(400).json({ error: 'Пользователь уже существует' });
    res.json({ success: true });
  });
});

// Вход
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
    if(!row) return res.status(400).json({ error: 'Пользователь не найден' });
    const valid = await bcrypt.compare(password, row.password);
    if(!valid) return res.status(400).json({ error: 'Неверный пароль' });
    // Получаем список всех пользователей
    db.all(`SELECT username FROM users WHERE username != ?`, [username], (err2, users) => {
      res.json({ success: true, username, users: users.map(u => u.username) });
    });
  });
});

// История сообщений между двумя пользователями
app.get('/messages/:user1/:user2', (req, res) => {
  const { user1, user2 } = req.params;
  db.all(
    `SELECT * FROM messages 
     WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?) 
     ORDER BY timestamp ASC`,
     [user1, user2, user2, user1],
     (err, rows) => {
       res.json(rows);
     }
  );
});

let clients = {};

wss.on('connection', (ws) => {
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if(data.type === 'login') {
        clients[data.username] = ws;
      }
      if(data.type === 'message') {
        const { from, to, message } = data;
        db.run(`INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)`, [from, to, message]);
        if(clients[to]) {
          clients[to].send(JSON.stringify({ from, message }));
        }
      }
    } catch(e) {
      console.log('Error', e);
    }
  });

  ws.on('close', () => {
    for(let user in clients) {
      if(clients[user] === ws) delete clients[user];
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
