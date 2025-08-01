// server.js

// --- 模块导入 ---
// 首先，加载创建新 require 所需的内置模块
const { createRequire } = require('node:module');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');
const sea = require('node:sea');
require = createRequire(__filename);

// --- 现在，我们可以像正常一样 require 所有第三方模块 ---
const express = require("express");
const crypto = require("crypto");
const multer = require("multer");
const { Server } = require("socket.io");
const mime = require('mime-types');
const bcrypt = require("bcrypt");
const { Level } = require("level");

// --- 健壮的路径管理 (这个逻辑是正确的，需要保留) ---
function getAppDataPath() {
    // 如果在SEA环境中运行，则在exe文件旁边创建一个'data'目录
    if (sea.isSea()) {
        const seaPath = path.dirname(process.execPath);
        return path.join(seaPath, 'data');
    }
    // 在开发环境中，直接使用项目根目录下的'data'目录
    return path.join(__dirname, 'data');
}

const appDataPath = getAppDataPath();
// 确保data目录存在
if (!fs.existsSync(appDataPath)) {
    fs.mkdirSync(appDataPath, { recursive: true });
}
console.log(`[路径管理] 所有应用数据将存储在: ${appDataPath}`);


// --- 初始化 ---
const runId = Math.floor(Math.random() * 10000);
console.log(`--- server.js 启动 (运行ID: ${runId}) ---`);

const dbPath = path.join(appDataPath, "chatdb");
const sslDir = path.join(appDataPath, "ssl");

console.log(`[调试信息] 数据库的绝对路径为: ${dbPath}`);
console.log(`[调试信息] SSL证书目录为: ${sslDir}`);

if (!fs.existsSync(sslDir)) fs.mkdirSync(sslDir);

// 初始化数据库
const db = new Level(dbPath, { valueEncoding: "json" });


// --- 后续代码保持不变 ---
const app = express();
const io = new Server();

let httpServer;
const saltRounds = 10;

let adminCredentials = null;
const rooms = {};

// --- SSL 配置 ---
let serverConfig = {
  httpPort: 3000,
  httpsPort: 3443,
  sslEnabled: false,
  sslCertPath: "",
  sslKeyPath: ""
};

// --- multer 配置 ---
const upload = multer({ dest: sslDir });

// --- 中间件 ---
app.use(express.json());

// ... 您的所有路由、Socket.IO 和服务器启动逻辑都保持不变 ...
// (此处省略了您文件中的其余所有代码，因为它们都是正确的，无需修改)

// --- 管理员状态 API ---
app.get("/admin/status", (req, res) => {
  res.json({ isConfigured: adminCredentials !== null });
});

// --- 设置管理员 ---
app.post("/setup/admin", async (req, res) => {
  if (adminCredentials) {
    return res.status(403).json({ error: "管理员账户已被设置。" });
  }
  const { username, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: "用户名或密码无效 (密码至少6位)。" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newAdmin = { username, password: hashedPassword };
    await db.put("admin:credentials", newAdmin);
    adminCredentials = newAdmin;
    console.log(`[管理员设置] 管理员 '${username}' 设置成功`);
    res.json({ success: true, message: "管理员账户设置成功！" });
  } catch (error) {
    console.error("设置管理员失败:", error);
    res.status(500).json({ error: "设置管理员失败" });
  }
});

// --- 管理员认证中间件 (增强健壮性) ---
async function adminAuthMiddleware(req, res, next) {
  if (!adminCredentials) {
    return res.status(403).json({ error: "管理员账户尚未设置。" });
  }
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Basic ") || auth.length < 10) {
    return res.status(401).send("Unauthorized: Missing credentials");
  }
  const [user, pass] = Buffer.from(auth.replace("Basic ", ""), "base64").toString().split(":");
  if (user !== adminCredentials.username) {
    return res.status(401).send("Unauthorized: Invalid credentials");
  }
  const match = await bcrypt.compare(pass, adminCredentials.password);
  if (!match) {
    return res.status(401).send("Unauthorized: Invalid credentials");
  }
  next();
}

// --- 加载服务器配置 ---
async function loadServerConfig() {
  try {
    const cfg = await db.get("server:config");
    serverConfig = { ...serverConfig, ...cfg };
    console.log("[配置] 加载服务器配置:", serverConfig);
  } catch (err) {
    if (err.code === "LEVEL_NOT_FOUND" || err.name === "NotFoundError") {
      console.log("[配置] 未找到服务器配置，使用默认并保存");
      await db.put("server:config", serverConfig);
    } else {
      console.error("[配置] 读取服务器配置失败:", err);
    }
  }
}

// --- 保存服务器配置 API ---
const adminRouter = express.Router();
adminRouter.use(adminAuthMiddleware);

adminRouter.get("/server-config", (req, res) => {
  res.json(serverConfig);
});

adminRouter.post("/server-config", async (req, res) => {
  const { httpPort, httpsPort, sslEnabled, sslCertPath, sslKeyPath } = req.body;

  if (sslEnabled) {
    if (!sslCertPath || !sslKeyPath) {
      return res.status(400).json({ error: "启用 SSL 时，证书和私钥路径不能为空。" });
    }
  }

  serverConfig.httpPort = Number(httpPort) || serverConfig.httpPort;
  serverConfig.httpsPort = Number(httpsPort) || serverConfig.httpsPort;
  serverConfig.sslEnabled = !!sslEnabled;
  serverConfig.sslCertPath = sslCertPath || "";
  serverConfig.sslKeyPath = sslKeyPath || "";

  try {
    await db.put("server:config", serverConfig);
    res.json({ success: true, message: "配置已保存，重启后生效。" });
    console.log("[管理员] 服务器配置已保存:", serverConfig);
  } catch (err) {
    console.error("[管理员] 保存服务器配置失败:", err);
    res.status(500).json({ error: "保存配置失败" });
  }
});

adminRouter.post("/upload-cert", upload.single("file"), async (req, res) => {
  try {
    const { type } = req.body;
    if (!req.file) return res.status(400).json({ error: "未选择上传文件" });

    const ext = path.extname(req.file.originalname);
    let destName = "";

    if (type === "cert") {
      destName = `server_cert${ext}`;
      serverConfig.sslCertPath = path.join(sslDir, destName);
    } else if (type === "key") {
      destName = `server_key${ext}`;
      serverConfig.sslKeyPath = path.join(sslDir, destName);
    } else {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "type 参数必须为 cert 或 key" });
    }

    const destPath = path.join(sslDir, destName);
    fs.renameSync(req.file.path, destPath);
    await db.put("server:config", serverConfig);

    res.json({ success: true, message: "上传成功", path: destPath });
    console.log(`[管理员] 上传证书文件: ${destPath}`);

  } catch (err) {
    console.error("[管理员] 上传证书失败:", err);
    res.status(500).json({ error: "上传失败" });
  }
});

// ---【修复】--- 使用优雅关停逻辑替换 process.exit()
adminRouter.post("/restart", (req, res) => {
  res.json({ success: true, message: "服务器正在进行关闭..." });
  console.log("[管理员] 触发服务器关闭");
  process.kill(process.pid, 'SIGTERM');
});

adminRouter.get("/rooms", (req, res) => {
  const data = Object.keys(rooms).map((room) => ({
    room,
    userCount: Object.keys(rooms[room].users).length,
    messages: rooms[room].messages.length,
  }));
  res.json(data);
});

adminRouter.get("/room-users", (req, res) => {
  const room = req.query.room;
  if (!rooms[room]) return res.status(404).json({ error: "聊天室不存在" });
  res.json({ room, users: Object.values(rooms[room].users) });
});

adminRouter.post("/kick-user", (req, res) => {
  const { room, username } = req.body;
  if (!rooms[room]) return res.status(404).json({ error: "聊天室不存在" });

  const targetSocketId = Object.entries(rooms[room].users).find(([id, name]) => name === username)?.[0];
  if (!targetSocketId) return res.status(404).json({ error: "用户不在该聊天室" });

  const targetSocket = io.sockets.sockets.get(targetSocketId);
  if (targetSocket) targetSocket.disconnect(true);

  if (rooms[room] && rooms[room].users[targetSocketId]) {
      delete rooms[room].users[targetSocketId];
  }

  res.json({ success: true, message: `已踢出 ${username}` });
});

adminRouter.post("/close-room", (req, res) => {
  const { room } = req.body;
  if (!rooms[room]) return res.status(404).json({ error: "聊天室不存在" });

  io.to(room).emit("system", "管理员已关停本聊天室。");
  io.in(room).disconnectSockets(true);
  delete rooms[room];
  res.json({ success: true, message: `聊天室 ${room} 已关停` });
});

adminRouter.post("/set-permission", async (req, res) => {
  const { username, canCreateRoom } = req.body;
  try {
    const userData = await db.get(`user:${username}`);
    userData.canCreateRoom = canCreateRoom;
    await db.put(`user:${username}`, userData);
    res.json({ success: true, message: `已更新 ${username} 的权限` });
  } catch (err) {
    if (err.code === 'LEVEL_NOT_FOUND' || err.name === 'NotFoundError') {
      return res.status(404).json({ error: "用户不存在" });
    }
    res.status(500).json({ error: "修改权限失败" });
  }
});

adminRouter.post("/broadcast", (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: "公告内容不能为空" });
  io.emit("system", `[公告] ${message}`);
  res.json({ success: true, message: "公告已发送" });
});

app.use("/admin", adminRouter);

// --- 用户注册 ---
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  console.log(`[注册流程] 收到用户 '${username}' 的注册请求。`);

  if (!username || !password) {
    return res.status(400).json({ error: "缺少用户名或密码" });
  }

  try {
    const existingUser = await db.get(`user:${username}`).catch(err => {
      if (err.code === 'LEVEL_NOT_FOUND' || err.name === 'NotFoundError') return null;
      throw err;
    });

    if (existingUser) {
      console.log(`[注册流程] 用户 '${username}' 已存在`);
      return res.status(400).json({ error: "用户名已存在" });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await db.put(`user:${username}`, { password: hashedPassword, canCreateRoom: false });
    console.log(`[注册流程] 用户 '${username}' 注册成功`);
    res.json({ success: true, message: "注册成功" });

  } catch (err) {
    console.error("[注册流程] 创建用户失败:", err);
    res.status(500).json({ error: "注册失败" });
  }
});

// ---【最终版】--- 根据是否在 SEA 环境中运行，动态提供静态文件
if (sea.isSea()) {
  console.log('[SEA] 在 Single Executable Application 模式下运行。');
  
  app.use((req, res, next) => {
    // 规范化请求路径，移除开头的 '/'
    let assetPath = req.path.slice(1);

    // 如果请求根目录，则默认为 index.html
    if (assetPath === '') {
      assetPath = 'index.html';
    }

    try {
      // 检查资源是否存在。我们使用 getAssetAsBlob 和 optional 标志，
      // 这样在找不到资源时它会返回 null 而不是抛出错误。
      const assetBlob = sea.getAssetAsBlob(assetPath, { optional: true });

      if (assetBlob) {
        // --- 资源存在 ---
        console.log(`[SEA] Serving asset: ${assetPath}`);
        const contentType = mime.lookup(assetPath) || 'application/octet-stream';
        res.setHeader('Content-Type', contentType);

        // 将 Blob 转换为 Buffer 并发送
        assetBlob.arrayBuffer().then(buffer => {
          res.send(Buffer.from(buffer));
        }).catch(err => {
          console.error(`[SEA] Error converting asset blob to buffer for ${assetPath}:`, err);
          next(err); // 如果转换出错，则传递错误
        });
      } else {
        // --- 资源不存在 ---
        // 明确地将请求传递给下一个中间件或路由处理器
        next();
      }
    } catch(err) {
        // 捕获 getAssetAsBlob 可能出现的其他未知错误
        console.error(`[SEA] An unexpected error occurred while looking for asset ${assetPath}:`, err);
        next(err);
    }
  });
} else {
  // 在常规模式下，从 'public' 文件夹提供文件
  console.log('[DEV] 在开发模式下运行，从 "public" 目录提供文件。');
  app.use(express.static(path.join(__dirname, 'public')));
}

// --- Socket.IO ---
io.on('connection', (socket) => {
    console.log(`[Socket.IO] 一个客户端已连接: ${socket.id}`);

    // --- 【【【 最终逻辑修复：区分游客和注册用户 】】】 ---
    socket.on('login', async ({ username, password }, callback) => {
        // 1. 基本验证
        if (!username || username.trim() === "") {
            return callback({ success: false, error: '用户名不能为空！' });
        }
        const trimmedUsername = username.trim();

        // 2. 如果没有提供密码，则按游客流程处理
        if (!password) {
            console.log(`[认证流程] 尝试作为游客登录: '${trimmedUsername}'`);
            try {
                // 安全检查：防止游客冒用已注册的用户名
                const existingUser = await db.get(`user:${trimmedUsername}`).catch(() => null);
                if (existingUser) {
                    return callback({ success: false, error: '此名称已被注册用户使用，请选择其他名称，或使用密码登录。' });
                }

                // 游客登录成功，为其设置一个临时的、可识别的身份
                socket.data.username = `${trimmedUsername} (游客)`;
                socket.data.isGuest = true;
                console.log(`[认证成功] 游客 '${socket.data.username}' (${socket.id}) 已登录。`);
                callback({ success: true, isAdmin: false, username: socket.data.username });

            } catch (err) {
                console.error(`[游客登录失败] 数据库查询时发生错误: ${err.message}`);
                callback({ success: false, error: '服务器错误，请稍后再试。' });
            }
        } 
        // 3. 如果提供了密码，则按注册用户流程处理
        else {
            console.log(`[认证流程] 尝试作为注册用户登录: '${trimmedUsername}'`);
            try {
                const userData = await db.get(`user:${trimmedUsername}`);
                const match = await bcrypt.compare(password, userData.password);
                if (!match) {
                    console.log(`[登录失败] 用户 '${trimmedUsername}' 提供了错误的密码。`);
                    return callback({ success: false, error: '用户名或密码错误' });
                }
                
                console.log(`[认证成功] 用户 '${trimmedUsername}' (${socket.id}) 已登录。`);
                socket.data.username = trimmedUsername;
                socket.data.isGuest = false;
                const isAdmin = adminCredentials && trimmedUsername === adminCredentials.username;
                socket.data.isAdmin = isAdmin;
                callback({ success: true, isAdmin: isAdmin, username: socket.data.username });

            } catch (err) {
                console.error(`[登录失败] 用户 '${trimmedUsername}' 不存在或数据库错误:`, err.message);
                callback({ success: false, error: '用户名或密码错误' });
            }
        }
    });

    // join, message, disconnect 等其他事件处理器保持不变
    socket.on('join', async ({ room, password, name, createIfNotExist }, callback) => {
        const username = socket.data.username;
        if (!username) {
            return callback({ success: false, error: '请先登录' });
        }
        
        if (createIfNotExist) {
            // 安全检查：只有注册用户才能创建房间
            if (socket.data.isGuest) {
                return callback({ success: false, error: '游客不能创建房间，请先注册。' });
            }
            try {
                const userData = await db.get(`user:${username}`);
                if (!userData.canCreateRoom) {
                    return callback({ success: false, error: '你没有创建房间的权限' });
                }
                if (rooms[room]) {
                    return callback({ success: false, error: `房间 '${room}' 已存在` });
                }
                const hashedPassword = await bcrypt.hash(password, saltRounds);
                rooms[room] = {
                    owner: username,
                    password: hashedPassword,
                    users: {},
                    messages: []
                };
                console.log(`[房间管理] 用户 '${username}' 创建了新房间: '${room}'`);
            } catch (err) {
                 console.error(`[创建房间失败] 用户: ${username}, 房间: ${room}`, err);
                 return callback({ success: false, error: '创建房间时发生服务器错误' });
            }
        }

        if (!rooms[room]) {
            return callback({ success: false, error: '聊天室不存在' });
        }

        const match = await bcrypt.compare(password, rooms[room].password);
        if (!match) {
            return callback({ success: false, error: '房间密码错误' });
        }

        if (socket.data.currentRoom) {
            socket.leave(socket.data.currentRoom);
            const oldRoom = rooms[socket.data.currentRoom];
            if (oldRoom && oldRoom.users) {
                delete oldRoom.users[socket.id];
                io.to(socket.data.currentRoom).emit('userList', Object.values(oldRoom.users));
            }
        }

        socket.join(room);
        socket.data.currentRoom = room;
        rooms[room].users[socket.id] = username;
        
        console.log(`[房间管理] 用户 '${username}' 加入了房间: '${room}'`);
        
        callback({ success: true, messages: rooms[room].messages });

        io.to(room).emit('system', `${username} 加入了聊天室`);
        io.to(room).emit('userList', Object.values(rooms[room].users));
    });

    socket.on('message', ({ text, isTemporary, duration }) => {
        const username = socket.data.username;
        const room = socket.data.currentRoom;

        if (!username || !room || !rooms[room]) return;

        const messageData = {
            text,
            user: username,
            time: new Date().toLocaleTimeString(),
            duration: duration || 5000
        };

        if (isTemporary) {
            io.to(room).emit('tempMessage', messageData);
        } else {
            rooms[room].messages.push(messageData);
            io.to(room).emit('message', messageData);
        }
    });

    socket.on('disconnect', () => {
        const username = socket.data.username;
        const room = socket.data.currentRoom;
        console.log(`[Socket.IO] 客户端已断开: ${socket.id} (用户: ${username})`);

        if (username && room && rooms[room] && rooms[room].users[socket.id]) {
            delete rooms[room].users[socket.id];
            io.to(room).emit('system', `${username} 离开了聊天室`);
            io.to(room).emit('userList', Object.values(rooms[room].users));
            console.log(`[房间管理] 用户 '${username}' 已从房间 '${room}' 移除`);
        }
    });
});

// --- 优雅关停 ---
async function gracefulShutdown() {
  console.log("\n[服务器关停] 收到关停信号，正在关闭...");
  if (httpServer) {
    httpServer.close(async () => {
      console.log("[服务器关停] HTTP/S 服务器已关闭。");
      if (db && typeof db.close === "function") {
        try {
          await db.close();
          console.log("[服务器关停] 数据库连接已关闭。");
        } catch (err) {
          console.error("[服务器关停] 关闭数据库时出错:", err);
        }
      }
      process.exit(0);
    });
    setTimeout(() => {
      console.error("[服务器关停] 无法在5秒内正常关闭，强制退出。");
      process.exit(1);
    }, 5000);
  } else {
    if (db && typeof db.close === "function" && db.status === 'open') {
        await db.close();
    }
    process.exit(0);
  }
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// --- 主启动 ---
async function startServer() {
  console.log("[启动流程] 正在检查管理员配置...");
  await loadServerConfig();

  try {
    const creds = await db.get("admin:credentials");
    if (creds) {
      adminCredentials = creds;
      console.log("[启动流程] 成功从数据库加载管理员数据。");
    }
  } catch (error) {
    if (error.code === 'LEVEL_NOT_FOUND' || error.name === 'NotFoundError') {
      console.log("[启动流程] 未找到管理员配置，待设置模式。");
    } else {
      console.error("[启动流程] 致命数据库错误:", error);
      process.exit(1);
    }
  }

  if (serverConfig.sslEnabled) {
    try {
      const httpsOptions = {
        key: fs.readFileSync(serverConfig.sslKeyPath),
        cert: fs.readFileSync(serverConfig.sslCertPath)
      };
      httpServer = https.createServer(httpsOptions, app);
      io.attach(httpServer);
      httpServer.listen(serverConfig.httpsPort, () => {
        console.log(`HTTPS 服务器已启动，监听端口: ${serverConfig.httpsPort}`);
      });

      const httpRedirectServer = http.createServer((req, res) => {
        const host = req.headers.host ? req.headers.host.split(":")[0] : "localhost";
        res.writeHead(301, {
          Location: `https://${host}:${serverConfig.httpsPort}${req.url}`
        });
        res.end();
      });
      httpRedirectServer.listen(serverConfig.httpPort, () => {
        console.log(`HTTP 重定向服务器已启动，监听端口: ${serverConfig.httpPort}`);
      });

    } catch (err) {
      console.error("[启动流程] 启动 HTTPS 失败，回退为 HTTP:", err.message);
      httpServer = http.createServer(app);
      io.attach(httpServer);
      httpServer.listen(serverConfig.httpPort, () => {
        console.log(`HTTP 服务器已启动，监听端口: ${serverConfig.httpPort}`);
      });
    }
  } else {
    httpServer = http.createServer(app);
    io.attach(httpServer);
    httpServer.listen(serverConfig.httpPort, () => {
      console.log(`HTTP 服务器已启动，监听端口: ${serverConfig.httpPort}`);
    });
  }

  console.log("======================================================");
  if (!adminCredentials) {
    console.log(">>> 管理员未设置，请访问 /admin.html 进行首次配置。");
  }
  console.log("======================================================");
}

startServer();