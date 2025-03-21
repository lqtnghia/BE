require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const moment = require("moment-timezone");
const fs = require("fs");

const app = express();
const port = 4010;

app.use(cors());
app.use(bodyParser.json({ limit: "100mb" })); // Tăng giới hạn payload
app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Đảm bảo thư mục uploads tồn tại
if (!fs.existsSync("./uploads/")) {
  fs.mkdirSync("./uploads/");
}

// Cấu hình Multer để xử lý upload hình ảnh
const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 } // Tăng giới hạn lên 100MB
}).single("image");

// Cấu hình MySQL với connection pool
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "root",
  database: "social_network",
  timezone: "+07:00",
  connectionLimit: 10
};

let db;
const ACCESS_TOKEN_SECRET =
  process.env.ACCESS_TOKEN_SECRET || "your_access_secret_key";
const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || "your_refresh_secret_key";

const timezone = "Asia/Ho_Chi_Minh";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER || "lqtnghia2602@gmail.com",
    pass: process.env.EMAIL_PASS || "xkdh kdrm byau yewl"
  }
});

async function connectDB() {
  try {
    db = await mysql.createPool(dbConfig);
    console.log("✅ Connected to MySQL with connection pool, timezone UTC+7");
  } catch (error) {
    console.error("❌ MySQL connection error:", error);
    process.exit(1);
  }
}

connectDB();

// Hàm tạo OTP ngẫu nhiên
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Đăng ký (Signup)
app.post("/api/signup", async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  let connection;
  try {
    connection = await db.getConnection();
    const [existingUser] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (existingUser.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await connection.execute(
      "INSERT INTO users (fullName, email, password, imageAva) VALUES (?, ?, ?, NULL)",
      [fullName, email, hashedPassword]
    );

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("❌ Signup error at:", moment().tz(timezone).format(), error);
    res.status(500).json({ message: "Server error", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Đăng nhập (Login) - Gửi OTP qua email
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt at:", moment().tz(timezone).format());

  if (!email || !password) {
    return res.status(400).json({ message: "Missing email or password" });
  }

  let connection;
  try {
    connection = await db.getConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    await connection.execute("DELETE FROM otps WHERE email = ?", [email]);

    const otp = generateOTP();
    const otpExpiry = moment().tz(timezone).add(10, "minutes").toDate();

    await connection.execute(
      "INSERT INTO otps (userId, email, otp, expiry) VALUES (?, ?, ?, ?)",
      [user.id, email, otp, otpExpiry]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER || "lqtnghia2602@gmail.com",
      to: email,
      subject: "Your OTP for Login",
      text: `Your OTP is: ${otp}. It will expire at ${moment(otpExpiry)
        .tz(timezone)
        .format("HH:mm DD/MM/YYYY")}.`
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: "OTP sent to your email", userId: user.id });
  } catch (error) {
    console.error("❌ Login error at:", moment().tz(timezone).format(), error);
    res.status(500).json({ message: "Server error", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Xác thực OTP
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ message: "Missing email or OTP" });
  }

  let connection;
  try {
    connection = await db.getConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM otps WHERE email = ? AND otp = ? AND expiry > NOW()",
      [email, otp]
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid or expired OTP" });
    }

    const [userRows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    const user = userRows[0];

    await connection.execute("DELETE FROM otps WHERE email = ? AND otp = ?", [
      email,
      otp
    ]);

    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = jwt.sign(
      { userId: user.id, email: user.email },
      REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    const tokenExpiry = moment().tz(timezone).add(7, "days").toDate();
    await connection.execute(
      "INSERT INTO refresh_tokens (userId, token, expiry) VALUES (?, ?, ?)",
      [user.id, refreshToken, tokenExpiry]
    );

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: { id: user.id, fullName: user.fullName, email: user.email }
    });
  } catch (error) {
    console.error(
      "❌ OTP verification error at:",
      moment().tz(timezone).format(),
      error
    );
    res.status(500).json({ message: "Server error", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Làm mới token
app.post("/api/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required" });
  }

  let connection;
  try {
    connection = await db.getConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM refresh_tokens WHERE token = ? AND expiry > NOW()",
      [refreshToken]
    );
    if (rows.length === 0) {
      return res
        .status(403)
        .json({ message: "Invalid or expired refresh token" });
    }

    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const userId = decoded.userId;

    const [userRows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [userId]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = userRows[0];
    const newAccessToken = jwt.sign(
      { userId: user.id, email: user.email },
      ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
    const newRefreshToken = jwt.sign(
      { userId: user.id, email: user.email },
      REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    const newTokenExpiry = moment().tz(timezone).add(7, "days").toDate();
    await connection.execute("DELETE FROM refresh_tokens WHERE token = ?", [
      refreshToken
    ]);
    await connection.execute(
      "INSERT INTO refresh_tokens (userId, token, expiry) VALUES (?, ?, ?)",
      [user.id, newRefreshToken, newTokenExpiry]
    );

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error(
      "❌ Refresh token error at:",
      moment().tz(timezone).format(),
      error
    );
    res
      .status(403)
      .json({ message: "Invalid refresh token", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Lấy thông tin user
app.get("/api/auth-user", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    connection = await db.getConnection();
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const [rows] = await connection.execute(
      "SELECT id, fullName, email, imageAva FROM users WHERE id = ?",
      [decoded.userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error(
      "❌ Auth-user error at:",
      moment().tz(timezone).format(),
      error
    );
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: error.message });
    }
    res.status(500).json({ message: "Server error", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Tạo bài post (Sửa để xử lý lỗi multer)
app.post("/api/posts", (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error("Multer error:", err);
      return res
        .status(400)
        .json({ message: err.message || "File upload error" });
    }

    console.log("Received POST /api/posts request:", {
      body: req.body,
      file: req.file
    });

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    let connection;
    try {
      const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
      const { content } = req.body;
      const imagePath = req.file ? req.file.filename : null;

      if (!content && !imagePath) {
        return res
          .status(400)
          .json({ message: "Content or image is required" });
      }

      connection = await db.getConnection();
      await connection.beginTransaction();

      const [result] = await connection.execute(
        "INSERT INTO posts (content, userId, image, createdAt) VALUES (?, ?, ?, NOW())",
        [content || null, decoded.userId, imagePath]
      );

      const [user] = await connection.execute(
        "SELECT fullName, imageAva FROM users WHERE id = ?",
        [decoded.userId]
      );

      if (user.length === 0) {
        throw new Error("User not found for this post");
      }

      await connection.commit();

      res.status(201).json({
        message: "Post created successfully",
        postId: result.insertId,
        content: content || null,
        image: imagePath ? `/uploads/${imagePath}` : null,
        createdAt: moment().tz(timezone).format(),
        fullName: user[0].fullName,
        imageAva: user[0].imageAva ? `/uploads/${user[0].imageAva}` : null,
        likes: [],
        comments: []
      });
    } catch (error) {
      if (connection) await connection.rollback();
      console.error("❌ Post error at:", moment().tz(timezone).format(), error);
      if (
        error.name === "TokenExpiredError" ||
        error.name === "JsonWebTokenError"
      ) {
        return res.status(401).json({ message: error.message });
      }
      res.status(500).json({ message: "Server error", error: error.message });
    } finally {
      if (connection) connection.release();
    }
  });
});

// Lấy danh sách bài post
app.get("/api/posts", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    console.log("Step 1 - Token received:", token);
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    console.log("Step 2 - Token decoded:", decoded);

    const limit = parseInt(req.query.limit, 10) || 10;
    const offset = parseInt(req.query.offset, 10) || 0;
    if (isNaN(limit) || isNaN(offset) || limit < 0 || offset < 0) {
      return res
        .status(400)
        .json({ message: "Limit and offset must be non-negative integers" });
    }
    console.log("Step 3 - Query params:", { limit, offset });

    connection = await db.getConnection();
    console.log("Step 4 - DB connection established");

    const query =
      "SELECT posts.id, posts.content, posts.image, posts.createdAt, users.fullName, users.imageAva " +
      "FROM posts " +
      "LEFT JOIN users ON posts.userId = users.id " +
      "ORDER BY posts.createdAt DESC " +
      `LIMIT ${limit} OFFSET ${offset}`;
    console.log("Step 5 - Executing query:", query);
    const [posts] = await connection.execute(query);
    console.log("Step 6 - Posts fetched:", posts);

    const formattedPosts = await Promise.all(
      posts.map(async (post) => {
        let likes = [];
        let comments = [];
        try {
          [likes] = await connection.execute(
            "SELECT userId, createdAt FROM likes WHERE postId = ?",
            [post.id]
          );
          console.log("Step 7 - Likes for post", post.id, ":", likes);
          [comments] = await connection.execute(
            "SELECT userId, content, createdAt FROM comments WHERE postId = ?",
            [post.id]
          );
          console.log("Step 8 - Comments for post", post.id, ":", comments);
        } catch (subError) {
          console.error(
            "Error fetching likes/comments for post",
            post.id,
            ":",
            subError
          );
          likes = [];
          comments = [];
        }
        return {
          id: post.id,
          content: post.content || "",
          image: post.image ? `/uploads/${post.image}` : null,
          createdAt: moment(post.createdAt).tz(timezone).format(),
          fullName: post.fullName || "Unknown User",
          imageAva: post.imageAva ? `/uploads/${post.imageAva}` : null,
          likes: likes.map((like) => ({
            userId: like.userId,
            createdAt: moment(like.createdAt).tz(timezone).format()
          })),
          comments: comments.map((comment) => ({
            userId: comment.userId,
            content: comment.content,
            createdAt: moment(comment.createdAt).tz(timezone).format()
          }))
        };
      })
    );

    console.log("Step 9 - Formatted posts:", formattedPosts);
    res.json(formattedPosts);
  } catch (error) {
    console.error(
      "❌ Get posts error at:",
      moment().tz(timezone).format(),
      error
    );
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: error.message });
    }
    res.status(500).json({ message: "Server error", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/api/search/users/:searchQuery", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Missing or invalid token" });
  }

  const token = authHeader.split(" ")[1];
  const { searchQuery } = req.params;
  const { limit = 10, offset = 0 } = req.query;

  if (!searchQuery || searchQuery.trim() === "") {
    return res.status(400).json({ message: "Search query is required" });
  }

  let connection;
  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const parsedLimit = parseInt(limit, 10);
    const parsedOffset = parseInt(offset, 10);
    if (
      isNaN(parsedLimit) ||
      isNaN(parsedOffset) ||
      parsedLimit < 0 ||
      parsedOffset < 0
    ) {
      return res.status(400).json({
        message: "Limit and offset must be non-negative integers"
      });
    }

    connection = await db.getConnection();

    const countQuery = `
      SELECT COUNT(*) as total
      FROM users
      WHERE (fullName LIKE ? OR email LIKE ?)
      AND id != ?
    `;
    const searchPattern = `%${searchQuery}%`;
    const [countResult] = await connection.execute(countQuery, [
      searchPattern,
      searchPattern,
      decoded.userId
    ]);
    const total = countResult[0].total;

    const query = `
      SELECT id, fullName, email, imageAva
      FROM users
      WHERE (fullName LIKE ? OR email LIKE ?)
      AND id != ?
      ORDER BY fullName ASC
      LIMIT ? OFFSET ?
    `;
    const [users] = await connection.execute(query, [
      searchPattern,
      searchPattern,
      decoded.userId,
      parsedLimit,
      parsedOffset
    ]);

    const formattedUsers = await Promise.all(
      users.map(async (user) => {
        let isFriend = false;
        try {
          const [friendship] = await connection.execute(
            `
            SELECT * FROM friendships
            WHERE (userId = ? AND friendId = ?) OR (userId = ? AND friendId = ?)
            AND status = 'accepted'
          `,
            [decoded.userId, user.id, user.id, decoded.userId]
          );
          isFriend = friendship.length > 0;
        } catch (friendshipError) {
          console.error(
            `Error checking friendship for user ${user.id}:`,
            friendshipError
          );
          isFriend = false; // Nếu lỗi, mặc định không phải bạn bè
        }
        return {
          id: user.id.toString(), // Chuyển id thành string để khớp với định dạng mong muốn
          fullName: user.fullName,
          email: user.email,
          imageAva: user.imageAva ? `/uploads/${user.imageAva}` : null, // Xử lý imageAva là NULL
          isFriend
        };
      })
    );

    res.status(200).json({
      total,
      offset: parsedOffset,
      limit: parsedLimit,
      users: formattedUsers
    });
  } catch (error) {
    console.error(
      "❌ Search users error at:",
      moment().tz(timezone).format(),
      error
    );
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Unauthorized: Invalid token" });
    }
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  } finally {
    if (connection) connection.release();
  }
});
const server = app.listen(port, () => {
  console.log(
    `🚀 Server running on http://localhost:${port}/api at:`,
    moment().tz(timezone).format()
  );
});
server.setTimeout(600000); // Tăng timeout lên 10 phút

// https://grok.com/chat/af033d86-e86b-45b4-8677-4b951a66aeda
