const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/database");
const transporter = require("../config/email");
const generateOTP = require("../utils/generateOTP");

const ACCESS_TOKEN_SECRET =
  process.env.ACCESS_TOKEN_SECRET || "your_access_secret_key";
const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || "your_refresh_secret_key";

// Đăng ký người dùng mới
const signup = async (req, res) => {
  const { fullName, email, password } = req.body;

  if (!fullName || !email || !password) {
    return res.status(400).json({ message: "Thiếu các trường bắt buộc" });
  }

  let connection;
  try {
    connection = await db.getConnection();

    const [existingUser] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (existingUser.length > 0) {
      return res.status(400).json({ message: "Người dùng đã tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.execute(
      "INSERT INTO users (fullName, email, password, imageAva) VALUES (?, ?, ?, NULL)",
      [fullName, email, hashedPassword]
    );

    res.status(201).json({ message: "Người dùng đã đăng ký thành công" });
  } catch (error) {
    console.error("Lỗi đăng ký:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Đăng nhập người dùng và gửi OTP
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Thiếu email hoặc mật khẩu" });
  }

  let connection;
  try {
    connection = await db.getConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res
        .status(401)
        .json({ message: "Thông tin đăng nhập không hợp lệ" });
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ message: "Thông tin đăng nhập không hợp lệ" });
    }

    await connection.execute("DELETE FROM otps WHERE email = ?", [email]);

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await connection.execute(
      "INSERT INTO otps (userId, email, otp, expiry) VALUES (?, ?, ?, ?)",
      [user.id, email, otp, otpExpiry]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER || "your_email@gmail.com",
      to: email,
      subject: "Mã OTP để đăng nhập",
      text: `Mã OTP của bạn là: ${otp}. Mã sẽ hết hạn sau 10 phút.`
    };

    await transporter.sendMail(mailOptions);
    res
      .status(200)
      .json({ message: "OTP đã được gửi đến email của bạn", userId: user.id });
  } catch (error) {
    console.error("Lỗi đăng nhập:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Quên mật khẩu và gửi email đặt lại mật khẩu
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  // Kiểm tra xem email có được cung cấp hay không
  if (!email) {
    return res.status(400).json({ message: "Email là bắt buộc" });
  }

  let connection;
  try {
    // Kết nối với cơ sở dữ liệu
    connection = await db.getConnection();

    // Kiểm tra xem người dùng có tồn tại không
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = rows[0];

    // Xóa các OTP hoặc token đặt lại mật khẩu cũ (nếu có)
    await connection.execute("DELETE FROM otps WHERE email = ?", [email]);

    // Tạo OTP hoặc token đặt lại mật khẩu
    const resetToken = generateOTP(); // Sử dụng hàm generateOTP đã có
    const tokenExpiry = new Date(Date.now() + 10 * 60 * 1000); // Hết hạn sau 10 phút

    // Lưu token vào cơ sở dữ liệu
    await connection.execute(
      "INSERT INTO otps (userId, email, otp, expiry) VALUES (?, ?, ?, ?)",
      [user.id, email, resetToken, tokenExpiry]
    );

    // Gửi email đặt lại mật khẩu
    const mailOptions = {
      from: process.env.EMAIL_USER || "your_email@gmail.com",
      to: email,
      subject: "Đặt lại mật khẩu",
      text: `Mã đặt lại mật khẩu của bạn là: ${resetToken}. Mã sẽ hết hạn sau 10 phút.`
    };

    await transporter.sendMail(mailOptions);

    // Trả về phản hồi thành công
    res
      .status(200)
      .json({ message: "Password reset email sent successfully." });
  } catch (error) {
    console.error("Lỗi quên mật khẩu:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Reset mật khẩu
const resetPassword = async (req, res) => {
  const { email, password } = req.body;

  // Kiểm tra các trường bắt buộc
  if (!email || !password) {
    return res.status(400).json({ message: "Email và mật khẩu là bắt buộc" });
  }

  let connection;
  try {
    connection = await db.getConnection();

    // Kiểm tra xem email có OTP hợp lệ không
    const [otpRows] = await connection.execute(
      "SELECT * FROM otps WHERE email = ? AND expiry > NOW()",
      [email]
    );
    if (otpRows.length === 0) {
      return res
        .status(401)
        .json({ message: "Bạn cần xác thực OTP trước khi reset mật khẩu" });
    }

    // Kiểm tra xem người dùng có tồn tại không
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    // Băm mật khẩu mới
    const hashedPassword = await bcrypt.hash(password, 10);

    // Cập nhật mật khẩu mới vào bảng users
    const [updateResult] = await connection.execute(
      "UPDATE users SET password = ? WHERE email = ?",
      [hashedPassword, email]
    );

    // Kiểm tra xem truy vấn có cập nhật thành công không
    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: "Không thể cập nhật mật khẩu" });
    }

    // Xóa OTP sau khi reset mật khẩu thành công
    await connection.execute("DELETE FROM otps WHERE email = ?", [email]);

    // Trả về phản hồi thành công
    res.status(200).json({ message: "Password reset successfully." });
  } catch (error) {
    console.error("Lỗi reset mật khẩu:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Xác minh OTP để đăng nhập
const verifyOTP = async (req, res) => {
  const { email, otp, flow } = req.body;

  // Kiểm tra các trường bắt buộc
  if (!email || !otp || !flow) {
    return res.status(400).json({ message: "Thiếu email, OTP hoặc flow" });
  }

  // Kiểm tra giá trị của flow
  if (!["login", "forgot-password"].includes(flow)) {
    return res.status(400).json({ message: "Giá trị flow không hợp lệ" });
  }

  let connection;
  try {
    connection = await db.getConnection();

    // Kiểm tra OTP
    const [rows] = await connection.execute(
      "SELECT * FROM otps WHERE email = ? AND otp = ? AND expiry > NOW()",
      [email, otp]
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: "OTP hoặc email không hợp lệ" });
    }

    // Không xóa OTP ở đây, để resetPassword xử lý nếu flow là forgot-password

    // Kiểm tra người dùng
    const [userRows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }
    const user = userRows[0];

    if (flow === "login") {
      // Flow login: Tạo accessToken và refreshToken
      const accessToken = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "5h" }
      );
      const refreshToken = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "7d" }
      );

      // Lưu refreshToken vào database
      const tokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 ngày
      await connection.execute(
        "INSERT INTO refresh_tokens (userId, token, expiry) VALUES (?, ?, ?)",
        [user.id, refreshToken, tokenExpiry]
      );

      // Xóa OTP sau khi đăng nhập thành công (flow login)
      await connection.execute("DELETE FROM otps WHERE email = ? AND otp = ?", [
        email,
        otp
      ]);

      return res.status(200).json({
        message: "Đăng nhập thành công",
        accessToken,
        refreshToken,
        user: { id: user.id, fullName: user.fullName, email: user.email }
      });
    } else if (flow === "forgot-password") {
      // Flow forgot password: Chỉ trả về thông báo thành công
      return res.status(200).json({
        message: "Xác minh OTP thành công"
      });
    }
  } catch (error) {
    console.error("Lỗi xác minh OTP:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Thay đổi mật khẩu
const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const authHeader = req.headers.authorization;

  // Kiểm tra header Authorization
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // Xác thực token
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;

    // Kiểm tra các trường bắt buộc
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Mật khẩu cũ và mới là bắt buộc" });
    }

    connection = await db.getConnection();

    // Lấy thông tin người dùng
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = rows[0];

    // Kiểm tra mật khẩu cũ
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Mật khẩu cũ không đúng" });
    }

    // Băm mật khẩu mới
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Cập nhật mật khẩu mới
    const [updateResult] = await connection.execute(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedNewPassword, userId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: "Không thể cập nhật mật khẩu" });
    }

    // (Tùy chọn) Xóa refresh token để yêu cầu đăng nhập lại
    await connection.execute("DELETE FROM refresh_tokens WHERE userId = ?", [
      userId
    ]);

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Lỗi đổi mật khẩu:", error);
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Làm mới token
const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token là bắt buộc" });
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
        .json({ message: "Refresh token không hợp lệ hoặc đã hết hạn" });
    }

    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const userId = decoded.userId;

    const [userRows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [userId]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = userRows[0];

    const newAccessToken = jwt.sign(
      { userId: user.id, email: user.email },
      ACCESS_TOKEN_SECRET,
      { expiresIn: "5h" }
    );
    const newRefreshToken = jwt.sign(
      { userId: user.id, email: user.email },
      REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    const newTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await connection.execute("DELETE FROM refresh_tokens WHERE token = ?", [
      refreshToken
    ]);
    await connection.execute(
      "INSERT INTO refresh_tokens (userId, token, expiry) VALUES (?, ?, ?)",
      [user.id, newRefreshToken, newTokenExpiry]
    );

    res
      .status(200)
      .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error("Lỗi làm mới token:", error);
    res
      .status(401)
      .json({ message: "Refresh token không hợp lệ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Lấy thông tin người dùng đã xác thực
const getAuthUser = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    console.log("Bước 1 - Nhận token:", token);
    console.log("Bước 2 - Kiểm tra db:", db);
    if (!db || typeof db.getConnection !== "function") {
      throw new Error("Database connection is not properly initialized");
    }
    console.log("Bước 3 - Kết nối cơ sở dữ liệu...");
    connection = await db.getConnection();
    console.log("Bước 4 - Giải mã token...");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    console.log("Bước 5 - Token giải mã:", decoded);
    console.log("Bước 6 - Truy vấn người dùng với userId:", decoded.userId);
    const [rows] = await connection.execute(
      "SELECT id, fullName, email, imageAva FROM users WHERE id = ?",
      [decoded.userId]
    );
    console.log("Bước 7 - Kết quả truy vấn:", rows);
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = rows[0];
    res.status(200).json({
      id: user.id.toString(),
      fullName: user.fullName,
      email: user.email,
      role: "regular",
      image: user.imageAva ? `/uploads/${user.imageAva}` : null
    });
  } catch (error) {
    console.error("Lỗi lấy thông tin người dùng:", error);
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Tạo bài đăng mới
const createPost = (upload) => async (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error("Lỗi Multer:", err);
      return res.status(400).json({ message: err.message || "Lỗi tải file" });
    }

    console.log("Nhận yêu cầu POST /posts:", {
      body: req.body,
      file: req.file
    });

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Không được phép truy cập" });
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
          .json({ message: "Nội dung hoặc hình ảnh là bắt buộc" });
      }

      connection = await db.getConnection();
      await connection.beginTransaction();

      const [result] = await connection.execute(
        "INSERT INTO posts (content, userId, image, createdAt) VALUES (?, ?, ?, NOW())",
        [content || null, decoded.userId, imagePath]
      );

      const [newPost] = await connection.execute(
        "SELECT createdAt FROM posts WHERE id = ?",
        [result.insertId]
      );

      const [user] = await connection.execute(
        "SELECT fullName, imageAva FROM users WHERE id = ?",
        [decoded.userId]
      );

      if (user.length === 0) {
        throw new Error("Không tìm thấy người dùng cho bài đăng này");
      }

      await connection.commit();

      res.status(201).json({
        id: result.insertId,
        content: content || null,
        image: imagePath ? `/uploads/${imagePath}` : null,
        createdAt: new Date(newPost[0].createdAt).toISOString(),
        fullName: user[0].fullName,
        imageAva: user[0].imageAva ? `/uploads/${user[0].imageAva}` : null,
        likes: [],
        comments: []
      });
    } catch (error) {
      if (connection) await connection.rollback();
      console.error("Lỗi tạo bài đăng:", error);
      if (
        error.name === "TokenExpiredError" ||
        error.name === "JsonWebTokenError"
      ) {
        return res.status(401).json({ message: "Không được phép truy cập" });
      }
      res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
    } finally {
      if (connection) connection.release();
    }
  });
};

// Lấy danh sách bài đăng
const getPosts = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    console.log("Bước 1 - Nhận token:", token);
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    console.log("Bước 2 - Giải mã token:", decoded);

    const limit = parseInt(req.query.limit, 10) || 10;
    const offset = parseInt(req.query.offset, 10) || 0;
    if (isNaN(limit) || isNaN(offset) || limit < 0 || offset < 0) {
      return res
        .status(400)
        .json({ message: "Limit và offset phải là số nguyên không âm" });
    }
    console.log("Bước 3 - Tham số truy vấn:", { limit, offset });

    connection = await db.getConnection();
    console.log("Bước 4 - Kết nối cơ sở dữ liệu thành công");

    const query =
      "SELECT posts.id, posts.content, posts.image, posts.createdAt, users.id AS userId, users.fullName, users.email, users.imageAva " +
      "FROM posts " +
      "LEFT JOIN users ON posts.userId = users.id " +
      "ORDER BY posts.createdAt DESC " +
      `LIMIT ${limit} OFFSET ${offset}`;
    console.log("Bước 5 - Thực thi truy vấn:", query);
    const [posts] = await connection.execute(query);
    console.log("Bước 6 - Lấy danh sách bài đăng:", posts);

    const formattedPosts = await Promise.all(
      posts.map(async (post) => {
        let likes = [];
        let comments = [];
        try {
          [likes] = await connection.execute(
            "SELECT userId, createdAt FROM likes WHERE postId = ?",
            [post.id]
          );
          console.log("Bước 7 - Lượt thích cho bài đăng", post.id, ":", likes);
          [comments] = await connection.execute(
            "SELECT userId, content, createdAt FROM comments WHERE postId = ?",
            [post.id]
          );
          console.log(
            "Bước 8 - Bình luận cho bài đăng",
            post.id,
            ":",
            comments
          );
        } catch (subError) {
          console.error(
            "Lỗi khi lấy lượt thích/bình luận cho bài đăng",
            post.id,
            ":",
            subError
          );
          likes = [];
          comments = [];
        }
        return {
          id: post.id.toString(),
          content: post.content || "",
          image: post.image ? `/uploads/${post.image}` : null,
          author: {
            id: post.userId.toString(),
            fullName: post.fullName || "Người dùng không xác định",
            email: post.email,
            role: "regular",
            image: post.imageAva ? `/uploads/${post.imageAva}` : null
          },
          likes: likes.map((like) => ({
            userId: like.userId.toString(),
            createdAt: new Date(like.createdAt).toISOString()
          })),
          comments: comments.map((comment) => ({
            userId: comment.userId.toString(),
            content: comment.content,
            createdAt: new Date(comment.createdAt).toISOString()
          })),
          createdAt: new Date(post.createdAt).toISOString(),
          updatedAt: new Date(post.createdAt).toISOString()
        };
      })
    );

    console.log("Bước 9 - Định dạng bài đăng:", formattedPosts);
    res.status(200).json(formattedPosts);
  } catch (error) {
    console.error("Lỗi lấy danh sách bài đăng:", error);
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Tìm kiếm người dùng
const searchUsers = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId; // Không ép kiểu thành chuỗi
    console.log("Step 2 - Current user ID:", currentUserId);

    const { searchQuery } = req.params;
    const limit = parseInt(req.query.limit, 10) || 10;
    const offset = parseInt(req.query.offset, 10) || 0;
    console.log("Step 3 - Search params:", { searchQuery, limit, offset });

    if (!searchQuery) {
      console.log("searchQuery is required");
      return res.status(400).json({ message: "searchQuery là bắt buộc" });
    }
    if (isNaN(limit) || isNaN(offset) || limit < 0 || offset < 0) {
      console.log("Invalid limit or offset");
      return res
        .status(400)
        .json({ message: "Limit và offset phải là số nguyên không âm" });
    }

    console.log("Step 4 - Get database connection");
    connection = await db.getConnection();
    console.log("Step 4.1 - Check current database");
    const [dbCheck] = await connection.execute("SELECT DATABASE() as db");
    console.log("Step 4.2 - Current database:", dbCheck[0].db);

    console.log("Step 5 - Count total users");
    const [totalResult] = await connection.execute(
      "SELECT COUNT(*) as total FROM users WHERE fullName LIKE ? AND id != ?",
      [`%${searchQuery}%`, currentUserId]
    );
    const total = totalResult[0].total;
    console.log("Step 6 - Total users:", total);

    console.log("Step 7 - Search users");
    const usersQuery = `SELECT id, fullName, imageAva, imagePublicId FROM users WHERE fullName LIKE ? AND id != ? ORDER BY fullName ASC LIMIT ${limit} OFFSET ${offset}`;
    console.log("Step 7.1 - Users query:", usersQuery);
    console.log("Step 7.2 - Users params:", [
      `%${searchQuery}%`,
      currentUserId
    ]);
    const [users] = await connection.query(usersQuery, [
      `%${searchQuery}%`,
      currentUserId
    ]);
    console.log("Step 8 - Found users:", users);

    const userIds = users.map((user) => parseInt(user.id, 10)); // Đảm bảo userIds là số
    console.log("Step 9 - User IDs:", userIds);

    let friends = [];
    let sentRequests = [];
    let receivedRequests = [];

    if (userIds.length > 0) {
      console.log("Step 10 - Check friends");
      const [friendRows] = await connection.execute(
        "SELECT userId, friendId FROM friends WHERE (userId = ? AND friendId IN (" +
          userIds.map(() => "?").join(",") +
          ")) OR (friendId = ? AND userId IN (" +
          userIds.map(() => "?").join(",") +
          "))",
        [currentUserId, ...userIds, currentUserId, ...userIds]
      );
      friends = friendRows;
      console.log("Step 11 - Friends:", friends);

      console.log("Step 12 - Check sent friend requests");
      console.log("Step 12.1 - Query params:", {
        currentUserId: currentUserId,
        userIds: userIds
      });
      const sentQuery =
        "SELECT senderId, receiverId FROM friend_requests WHERE senderId = ? AND receiverId IN (" +
        userIds.map(() => "?").join(",") +
        ") AND status = ?";
      console.log("Step 12.2 - Sent query:", sentQuery);
      console.log("Step 12.3 - Query values:", [
        currentUserId,
        ...userIds,
        "pending"
      ]);
      const [sentRows] = await connection.execute(sentQuery, [
        currentUserId,
        ...userIds,
        "pending"
      ]);
      sentRequests = sentRows;
      console.log("Step 13 - Sent requests:", sentRequests);
      console.log(
        "Step 13.1 - Sent requests map:",
        sentRequests.map((req) => req.receiverId)
      );

      console.log("Step 14 - Check received friend requests");
      const receivedQuery =
        "SELECT senderId, receiverId FROM friend_requests WHERE receiverId = ? AND senderId IN (" +
        userIds.map(() => "?").join(",") +
        ") AND status = ?";
      console.log("Step 14.1 - Received query:", receivedQuery);
      const [receivedRows] = await connection.execute(receivedQuery, [
        currentUserId,
        ...userIds,
        "pending"
      ]);
      receivedRequests = receivedRows;
      console.log("Step 15 - Received requests:", receivedRequests);
    } else {
      console.log("Step 10 - No user IDs, skipping relationship checks");
    }

    const friendsMap = new Set();
    friends.forEach((friend) => {
      if (friend.userId === currentUserId) {
        friendsMap.add(friend.friendId);
      } else if (friend.friendId === currentUserId) {
        friendsMap.add(friend.userId);
      }
    });
    console.log("Step 15.1 - Friends map:", Array.from(friendsMap));

    const sentRequestsMap = new Set(sentRequests.map((req) => req.receiverId));
    const receivedRequestsMap = new Set(
      receivedRequests.map((req) => req.senderId)
    );

    const formattedUsers = users.map((user) => ({
      id: user.id.toString(),
      fullName: user.fullName,
      image: user.imageAva ? `/uploads/${user.imageAva}` : null,
      imagePublicId: user.imagePublicId || null,
      isFriend: friendsMap.has(user.id),
      requestSent: sentRequestsMap.has(user.id),
      requestReceived: receivedRequestsMap.has(user.id)
    }));

    console.log("Step 16 - Formatted users:", formattedUsers);

    res.status(200).json({
      total,
      offset,
      limit,
      users: formattedUsers
    });
  } catch (error) {
    console.error("Lỗi tìm kiếm người dùng:", {
      error: error.message,
      stack: error.stack
    });
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// SendFriendRequest
const sendFriendRequest = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId;
    console.log("Step 2 - Current user ID:", currentUserId);

    const { friendId } = req.body;
    console.log("Step 3 - Friend ID:", friendId);

    if (!friendId) {
      console.log("friendId is required");
      return res.status(400).json({ message: "friendId là bắt buộc" });
    }

    const friendIdNum = parseInt(friendId, 10);
    if (isNaN(friendIdNum)) {
      console.log("Invalid friendId");
      return res.status(400).json({ message: "friendId không hợp lệ" });
    }

    if (friendIdNum === currentUserId) {
      console.log("Cannot send friend request to yourself");
      return res
        .status(400)
        .json({ message: "Không thể gửi yêu cầu kết bạn cho chính mình" });
    }

    console.log("Step 4 - Get database connection");
    connection = await db.getConnection();

    console.log("Step 5 - Check if friendId exists");
    const [friendRows] = await connection.execute(
      "SELECT id, fullName, imageAva FROM users WHERE id = ?",
      [friendIdNum]
    );
    if (friendRows.length === 0) {
      console.log("Friend not found");
      return res.status(400).json({ message: "Người dùng không tồn tại" });
    }

    console.log("Step 6 - Check if already friends");
    const [friendshipRows] = await connection.execute(
      "SELECT * FROM friends WHERE (userId = ? AND friendId = ?) OR (userId = ? AND friendId = ?)",
      [currentUserId, friendIdNum, friendIdNum, currentUserId]
    );
    if (friendshipRows.length > 0) {
      console.log("Already friends");
      return res.status(400).json({ message: "Hai người đã là bạn bè" });
    }

    console.log("Step 7 - Check if request already exists");
    const [requestRows] = await connection.execute(
      "SELECT * FROM friend_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
      [currentUserId, friendIdNum]
    );
    if (requestRows.length > 0) {
      console.log("Friend request already sent");
      return res
        .status(400)
        .json({ message: "Yêu cầu kết bạn đã được gửi trước đó" });
    }

    // console.log("Step 8 - Send friend request");
    // const [result] = await connection.execute(
    //   "INSERT INTO friend_requests (senderId, receiverId, status, createdAt, updatedAt) VALUES (?, ?, 'pending', NOW(), NOW())",
    //   [currentUserId, friendIdNum]
    // );

    // // Lấy thông tin người gửi
    // const [senderRows] = await connection.execute(
    //   "SELECT id, fullName, imageAva FROM users WHERE id = ?",
    //   [currentUserId]
    // );
    // const sender = senderRows[0];

    // // Dữ liệu lời mời kết bạn
    // const friendRequestData = {
    //   id: result.insertId.toString(),
    //   sender: {
    //     id: sender.id.toString(),
    //     fullName: sender.fullName,
    //     image: sender.imageAva ? `/uploads/${sender.imageAva}` : null
    //   },
    //   createdAt: new Date().toISOString()
    // };

    // // Phát sự kiện tới người nhận
    // req.io
    //   .to(friendIdNum.toString())
    //   .emit("newFriendRequest", friendRequestData);

    // // Phát sự kiện tới người gửi (nếu cần hiển thị trong FriendRequest của người gửi)
    // req.io.to(currentUserId.toString()).emit("friendRequestSent", {
    //   receiverId: friendIdNum.toString(),
    //   ...friendRequestData
    // });

    // console.log("Step 9 - Friend request sent successfully");
    // res.status(200).json({ message: "Friend request sent successfully." });
    console.log("Step 8 - Send friend request");
    const [result] = await connection.execute(
      "INSERT INTO friend_requests (senderId, receiverId, status, createdAt, updatedAt) VALUES (?, ?, 'pending', NOW(), NOW())",
      [currentUserId, friendIdNum]
    );

    // Lấy thông tin người gửi
    const [senderRows] = await connection.execute(
      "SELECT id, fullName, imageAva FROM users WHERE id = ?",
      [currentUserId]
    );
    const sender = senderRows[0];

    // Dữ liệu lời mời kết bạn
    const friendRequestData = {
      id: result.insertId.toString(),
      sender: {
        id: sender.id.toString(),
        fullName: sender.fullName,
        image: sender.imageAva ? `/uploads/${sender.imageAva}` : null
      },
      createdAt: new Date().toISOString()
    };

    // Phát sự kiện tới người nhận
    req.io
      .to(friendIdNum.toString())
      .emit("newFriendRequest", friendRequestData);

    // Phát sự kiện tới người gửi (nếu cần hiển thị trong FriendRequest của người gửi)
    req.io.to(currentUserId.toString()).emit("friendRequestSent", {
      receiverId: friendIdNum.toString(),
      ...friendRequestData
    });

    console.log("Step 9 - Friend request sent successfully");
    res.status(200).json({ message: "Friend request sent successfully." });
  } catch (error) {
    console.error("Lỗi gửi yêu cầu kết bạn:", {
      error: error.message,
      stack: error.stack
    });
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Lấy danh sách yêu cầu kết bạn đang chờ xử lý
const getPendingFriendRequests = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId;
    console.log("Step 2 - Current user ID:", currentUserId);

    console.log("Step 3 - Get database connection");
    connection = await db.getConnection();

    console.log("Step 4 - Fetch pending friend requests");
    const [requestRows] = await connection.execute(
      `SELECT fr.id, fr.senderId, fr.createdAt, 
              u.id AS userId, u.fullName, u.imageAva 
       FROM friend_requests fr 
       JOIN users u ON fr.senderId = u.id 
       WHERE fr.receiverId = ? AND fr.status = 'pending' 
       ORDER BY fr.createdAt DESC`,
      [currentUserId]
    );
    console.log("Step 5 - Pending requests:", requestRows);

    const formattedRequests = requestRows.map((request) => ({
      id: request.id.toString(),
      sender: {
        id: request.userId.toString(),
        fullName: request.fullName,
        image: request.imageAva ? `/uploads/${request.imageAva}` : null
      },
      createdAt: new Date(request.createdAt).toISOString()
    }));

    console.log("Step 6 - Formatted pending requests:", formattedRequests);
    res.status(200).json(formattedRequests);
  } catch (error) {
    console.error("Lỗi lấy danh sách yêu cầu kết bạn đang chờ:", {
      error: error.message,
      stack: error.stack
    });
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

module.exports = {
  signup,
  login,
  verifyOTP,
  refreshToken,
  getAuthUser,
  createPost,
  getPosts,
  searchUsers,
  sendFriendRequest,
  getPendingFriendRequests,
  forgotPassword,
  resetPassword,
  changePassword
};
