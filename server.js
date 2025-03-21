// 引入所需模块
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const express = require('express');
const cors = require('cors'); // 新增：引入 cors 模块
const app = express();
const server = require('http').createServer(app);
const wss = new WebSocket.Server({ server });

// 配置 Express 中间件
app.use(express.json());
app.use(cors({ // 新增：启用 CORS，允许特定源
  origin: 'http://chatliu.rf.gd', // 允许你的 InfinityFree 域名
  methods: ['GET', 'POST'],       // 允许的 HTTP 方法
  allowedHeaders: ['Content-Type'] // 允许的请求头
}));

// 初始化 SQLite 数据库
const db = new sqlite3.Database('.data/chat.db', (err) => {
  if (err) console.error('数据库连接失败:', err.message);
  else console.log('数据库连接成功');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `, (err) => {
    if (err) console.error('创建用户表失败:', err.message);
    else console.log('用户表创建成功');
  });

  // 创建消息表
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      text TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) console.error('创建消息表失败:', err.message);
    else console.log('消息表创建成功');
  });
});

// 注册接口
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
      if (err) {
        console.log('数据库插入错误:', err.message);
        return res.status(400).json({ error: '用户名已存在' });
      }
      res.json({ success: true, message: '注册成功' });
    });
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ error: '服务器错误' });
  }
});

// 登录接口
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err || !row) return res.status(400).json({ error: '用户不存在' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ error: '密码错误' });
    res.json({ success: true, username });
  });
});

// WebSocket 连接处理
wss.on('connection', (ws) => {
  console.log('新客户端已连接');

  // 发送历史消息
  db.all('SELECT username, text, timestamp FROM messages ORDER BY timestamp ASC LIMIT 50', (err, rows) => {
    if (err) {
      console.error('查询历史消息失败:', err.message);
      return;
    }
    ws.send(JSON.stringify({ type: 'history', messages: rows }));
  });

  
  ws.on('message', (message) => {
    let data;
    try {
      data = JSON.parse(message.toString('utf8'));
    } catch (error) {
      console.error('消息解析失败:', error);
      return;
    }
    if (data.type === 'auth') {
      ws.username = data.username;
      console.log(`${ws.username} 已认证`);
      ws.send(JSON.stringify({ type: 'auth_success', username: ws.username }));
    } else if (data.type === 'message' && ws.username) {
      //const formattedMessage = `${ws.username}: ${data.text}`;  //这是广播的内容
      //将广播的内容改为json格式
      const formattedMessage = {type:'message',username:ws.username,text:data.text,timestamp: new Date().toISOString()};  //这是广播的内容
      // 保存消息到数据库
      db.run('INSERT INTO messages (username, text) VALUES (?, ?)', [ws.username, data.text], (err) => {
        if (err) console.error('保存消息失败:', err.message);
      });

      // 广播消息
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(formattedMessage));
        }
      });
    }
  });
  ws.on('close', () => {
    console.log(`${ws.username || '未知用户'} 已断开`);
  });
});

// 启动服务器
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`服务器运行在端口 ${PORT}`);
});