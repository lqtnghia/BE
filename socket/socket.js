const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");

const initializeSocket = (server) => {
  const io = new Server(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    },
    path: "/socket.io"
  });

  // Định nghĩa namespace /api
  const apiNamespace = io.of("/api");

  apiNamespace.use((socket, next) => {
    console.log("Nhận handshake trong namespace /api:", socket.handshake);
    const token = socket.handshake.auth.token;
    if (!token) {
      console.error("Không có token được cung cấp");
      return next(new Error("Lỗi xác thực: Không có token"));
    }
    try {
      const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
      console.log("Token đã được giải mã:", decoded);
      socket.user = decoded;
      next();
    } catch (error) {
      console.error("Xác minh token thất bại:", error.message);
      next(new Error("Lỗi xác thực: Token không hợp lệ"));
    }
  });

  apiNamespace.on("connection", (socket) => {
    console.log(
      "Client đã kết nối đến namespace /api:",
      socket.id,
      "User:",
      socket.user
    );
    socket.on("join", (userId) => {
      if (socket.user.userId === parseInt(userId, 10)) {
        socket.join(userId.toString());
        console.log(`User ${userId} đã tham gia phòng ${userId}`);
      } else {
        console.log("Thử tham gia không được phép");
      }
    });
    socket.on("disconnect", (reason) => {
      console.log(
        "Client đã ngắt kết nối từ namespace /api:",
        socket.id,
        "Lý do:",
        reason
      );
    });
  });

  return io;
};

module.exports = { initializeSocket };
