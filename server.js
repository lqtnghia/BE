// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const authRoutes = require("./routes/authRoutes");
const http = require("http");
const { initializeSocket } = require("./socket/socket");

const app = express();
const port = 4010;

const server = http.createServer(app);

// Khởi tạo Socket.IO
const io = initializeSocket(server);

//Middleware để truyền io vào request
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: "100mb" }));
app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Đảm bảo thư mục uploads tồn tại
if (!fs.existsSync("./uploads/")) {
  fs.mkdirSync("./uploads/");
}

// Sử dụng routes với tiền tố /api
app.use("/api", authRoutes);

// Khởi động server
server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
