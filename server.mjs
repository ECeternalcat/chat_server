// server.mjs (最终整合优化版)

import express from "express";
import http from "http";
import https from "https";              // 新增：https模块
import path from "path";
import crypto from "crypto";
import { Level } from "level";
import { fileURLToPath } from "url";
import { dirname } from "path";
import bcrypt from "bcrypt";
import multer from "multer";            // 新增：multer 用于上传

// --- 初始化 ---
const runId = Math.floor(Math.random() * 10000);
console.log(`--- server.mjs 启动 (运行ID: ${runId}) ---`);
console.log(`当前工作目录 (数据库将创建在这里): ${process.cwd()}`);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 使用 __dirname 确保数据库路径正确
const dbPath = path.join(__dirname, "chatdb");
console.log(`[调试信息] 数据库的绝对路径为: ${dbPath}`);
const db = new Level(dbPath, { valueEncoding: "json" });

const app = express();

let httpServer;                      // 新增：服务器变量（后续根据SSL启用情况启动不同服务）
let io;                             // socket.io 实例（后面根据httpServer绑定）
const saltRounds = 10;

let adminCredentials = null;
const rooms = {}; // 内存中的房间信息

// --- 新增：SSL 配置 ---
// 默认配置，启动时会从数据库加载
let serverConfig = {
  httpPort: 3000,
  httpsPort: 3443,
  sslEnabled: false,
  sslCertPath: "",
  sslKeyPath: ""
};

const sslDir = path.join(__dirname, "ssl");

// 确保 ssl 文件夹存在
import fs from "fs";
if (!fs.existsSync(sslDir)) fs.mkdirSync(sslDir);

// --- multer 配置，用于上传文件 ---
const upload = multer({ dest: sslDir });

// --- 中间件 ---
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

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

// --- 新增：加载服务器配置 ---
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

// --- 新增：保存服务器配置 API ---
const adminRouter = express.Router();
adminRouter.use(adminAuthMiddleware);

// 获取当前配置
adminRouter.get("/server-config", (req, res) => {
  res.json(serverConfig);
});

// 更新配置（端口、SSL开关、证书路径）
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

// --- 新增：上传证书和私钥接口 ---
// 上传字段名 file，参数 type=cert/key
adminRouter.post("/upload-cert", upload.single("file"), async (req, res) => {
  try {
    const { type } = req.body; // 证书(cert) 或 私钥(key)
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
      return res.status(400).json({ error: "type 参数必须为 cert 或 key" });
    }

    const destPath = path.join(sslDir, destName);

    // 移动文件到 ssl 文件夹并覆盖
    fs.renameSync(req.file.path, destPath);

    // 保存路径配置
    await db.put("server:config", serverConfig);

    res.json({ success: true, message: "上传成功", path: destPath });
    console.log(`[管理员] 上传证书文件: ${destPath}`);

  } catch (err) {
    console.error("[管理员] 上传证书失败:", err);
    res.status(500).json({ error: "上传失败" });
  }
});

// --- 新增：立即重启服务器接口 ---
adminRouter.post("/restart", (req, res) => {
  res.json({ success: true, message: "服务器正在关闭..." });
  console.log("[管理员] 触发服务器关闭");
  setTimeout(() => process.exit(0), 1000);
});

// --- 其余管理员接口保持不变 ---
// （把之前 adminRouter 其他接口代码放进这里，保持不变）
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

  delete rooms[room].users[targetSocketId];

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
// (保持不变)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  console.log(`[注册流程] 收到用户 '${username}' 的注册请求。`);

  if (!username || !password) {
    return res.status(400).json({ error: "缺少用户名或密码" });
  }

  try {
    const existingUser = await db.get(`user:${username}`).catch(err => {
      if (err.code === 'LEVEL_NOT_FOUND' || err.name === 'NotFoundError') return null;
      throw err; // 其他错误直接抛出
    });

    if (existingUser) {
      console.log(`[注册流程] 用户 '${username}' 已存在`);
      return res.status(400).json({ error: "用户名已存在" });
    }

    // 用户不存在，正常注册
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await db.put(`user:${username}`, { password: hashedPassword, canCreateRoom: false });
    console.log(`[注册流程] 用户 '${username}' 注册成功`);
    res.json({ success: true, message: "注册成功" });

  } catch (err) {
    console.error("[注册流程] 创建用户失败:", err);
    res.status(500).json({ error: "注册失败" });
  }
});

// --- Socket.IO ---
// (保持不变)
io = new (await import("socket.io")).Server();  // 先声明变量，稍后启动后绑定

// --- 优雅关停 ---
// (保持不变)
async function gracefulShutdown() {
  console.log("\n[服务器关停] 收到关停信号，正在关闭...");
  if (httpServer) {
    httpServer.close(async () => {
      console.log("[服务器关停] HTTP 服务器已关闭。");
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
    process.exit(0);
  }
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// --- 主启动 ---
// 修改启动流程，支持根据配置启动 HTTP 或 HTTPS 服务器
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

      // 同时启动一个 HTTP 服务器，做 301 重定向到 HTTPS
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
      console.error("[启动流程] 启动 HTTPS 失败，回退为 HTTP:", err);
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
