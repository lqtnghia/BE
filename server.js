require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const http = require("http");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const authRoutes = require("./src/routes/authRoutes.js");

const app = express();
const server = http.createServer(app);

// Cấu hình CORS cho Socket.IO
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"],
    credentials: true
  },
  path: "/api/socket.io"
});

const port = 4010;
const ACCESS_TOKEN_SECRET =
  process.env.ACCESS_TOKEN_SECRET || "your_access_secret_key";

// Middleware để xác thực token và gán userId vào socket
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    console.log("Authentication error: No token provided");
    return next(new Error("Authentication error: No token provided"));
  }

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    socket.userId = decoded.userId;
    console.log(`Socket.IO: Token verified for userId: ${decoded.userId}`);
    next();
  } catch (error) {
    console.log("Authentication error: Invalid token", error.message);
    next(new Error("Authentication error: Invalid token"));
  }
});

// Lắng nghe kết nối từ client
io.on("connection", (socket) => {
  const timestamp = new Date().toISOString();
  console.log(
    `[${timestamp}] User connected: ${socket.userId} (Socket ID: ${socket.id})`
  );
  socket.join(socket.userId);

  socket.on("disconnect", () => {
    const disconnectTimestamp = new Date().toISOString();
    console.log(
      `[${disconnectTimestamp}] User disconnected: ${socket.userId} (Socket ID: ${socket.id})`
    );
  });
});

// Middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  })
);
app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

if (!fs.existsSync("/uploads/")) {
  fs.mkdirSync("/uploads/");
}

app.use(
  "/api",
  (req, res, next) => {
    req.io = io;
    next();
  },
  authRoutes
);

server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
