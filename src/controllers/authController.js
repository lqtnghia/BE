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
    // console.error("Lỗi đăng ký:", error);
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
    // console.error("Lỗi đăng nhập:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Quên mật khẩu và gửi email đặt lại mật khẩu
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email là bắt buộc" });
  }

  let connection;
  try {
    connection = await db.getConnection();

    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = rows[0];

    await connection.execute("DELETE FROM otps WHERE email = ?", [email]);

    const resetToken = generateOTP();
    const tokenExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await connection.execute(
      "INSERT INTO otps (userId, email, otp, expiry) VALUES (?, ?, ?, ?)",
      [user.id, email, resetToken, tokenExpiry]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER || "your_email@gmail.com",
      to: email,
      subject: "Đặt lại mật khẩu",
      text: `Mã đặt lại mật khẩu của bạn là: ${resetToken}. Mã sẽ hết hạn sau 10 phút.`
    };

    await transporter.sendMail(mailOptions);

    res
      .status(200)
      .json({ message: "Password reset email sent successfully." });
  } catch (error) {
    // console.error("Lỗi quên mật khẩu:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Reset mật khẩu
const resetPassword = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email và mật khẩu là bắt buộc" });
  }

  let connection;
  try {
    connection = await db.getConnection();

    const [otpRows] = await connection.execute(
      "SELECT * FROM otps WHERE email = ? AND expiry > NOW()",
      [email]
    );
    if (otpRows.length === 0) {
      return res
        .status(401)
        .json({ message: "Bạn cần xác thực OTP trước khi reset mật khẩu" });
    }

    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [updateResult] = await connection.execute(
      "UPDATE users SET password = ? WHERE email = ?",
      [hashedPassword, email]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: "Không thể cập nhật mật khẩu" });
    }

    await connection.execute("DELETE FROM otps WHERE email = ?", [email]);

    res.status(200).json({ message: "Password reset successfully." });
  } catch (error) {
    // console.error("Lỗi reset mật khẩu:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Xác minh OTP để đăng nhập
const verifyOTP = async (req, res) => {
  const { email, otp, flow } = req.body;

  if (!email || !otp || !flow) {
    return res.status(400).json({ message: "Thiếu email, OTP hoặc flow" });
  }

  if (!["login", "forgot-password"].includes(flow)) {
    return res.status(400).json({ message: "Giá trị flow không hợp lệ" });
  }

  let connection;
  try {
    connection = await db.getConnection();

    const [rows] = await connection.execute(
      "SELECT * FROM otps WHERE email = ? AND otp = ? AND expiry > NOW()",
      [email, otp]
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: "OTP hoặc email không hợp lệ" });
    }

    const [userRows] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }
    const user = userRows[0];

    if (flow === "login") {
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

      const tokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      await connection.execute(
        "INSERT INTO refresh_tokens (userId, token, expiry) VALUES (?, ?, ?)",
        [user.id, refreshToken, tokenExpiry]
      );

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
      return res.status(200).json({
        message: "Xác minh OTP thành công"
      });
    }
  } catch (error) {
    // console.error("Lỗi xác minh OTP:", error);
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
  }
};

// Thay đổi mật khẩu
const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;

    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ message: "Mật khẩu cũ và mới là bắt buộc" });
    }

    connection = await db.getConnection();

    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = rows[0];

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Mật khẩu cũ không đúng" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    const [updateResult] = await connection.execute(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedNewPassword, userId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ message: "Không thể cập nhật mật khẩu" });
    }

    await connection.execute("DELETE FROM refresh_tokens WHERE userId = ?", [
      userId
    ]);

    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    // console.error("Lỗi đổi mật khẩu:", error);
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
    // console.error("Lỗi làm mới token:", error);
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
    // console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // console.log("Bước 1 - Nhận token:", token);
    // console.log("Bước 2 - Kiểm tra db:", db);
    if (!db || typeof db.getConnection !== "function") {
      throw new Error("Database connection is not properly initialized");
    }
    // console.log("Bước 3 - Kết nối cơ sở dữ liệu...");
    connection = await db.getConnection();
    // console.log("Bước 4 - Giải mã token...");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    // console.log("Bước 5 - Token giải mã:", decoded);
    // console.log("Bước 6 - Truy vấn người dùng với userId:", decoded.userId);
    const [rows] = await connection.execute(
      "SELECT id, fullName, email, imageAva FROM users WHERE id = ?",
      [decoded.userId]
    );
    // console.log("Bước 7 - Kết quả truy vấn:", rows);
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
    // console.error("Lỗi lấy thông tin người dùng:", error);
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
      // console.error("Lỗi Multer:", err);
      return res.status(400).json({ message: err.message || "Lỗi tải file" });
    }

    // console.log("Nhận yêu cầu POST /posts:", {
    //   body: req.body,
    //   file: req.file
    // });

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
      // console.error("Lỗi tạo bài đăng:", error);
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
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;

    connection = await db.getConnection();
    await connection.beginTransaction();

    // Lấy danh sách bài đăng của người dùng hiện tại và bạn bè
    const [posts] = await connection.execute(
      `
      SELECT p.*, u.fullName, u.imageAva 
      FROM posts p 
      JOIN users u ON p.userId = u.id 
      WHERE p.userId = ? 
      OR p.userId IN (
        SELECT friendId 
        FROM friends 
        WHERE userId = ? 
        UNION 
        SELECT userId 
        FROM friends 
        WHERE friendId = ?
      )
      ORDER BY p.createdAt DESC
      `,
      [userId, userId, userId]
    );

    // Lấy danh sách lượt thích và bình luận cho từng bài đăng
    const formattedPosts = await Promise.all(
      posts.map(async (post) => {
        const [likes] = await connection.execute(
          "SELECT userId FROM likes WHERE postId = ?",
          [post.id]
        );

        const [comments] = await connection.execute(
          `
          SELECT c.*, u.fullName, u.imageAva 
          FROM comments c 
          LEFT JOIN users u ON c.userId = u.id 
          WHERE c.postId = ? 
          ORDER BY c.createdAt DESC
          `,
          [post.id]
        );

        return {
          ...post,
          image: post.image ? `/uploads/${post.image}` : null,
          imageAva: post.imageAva ? `/uploads/${post.imageAva}` : null,
          likes: likes.map((like) => ({ userId: like.userId })),
          comments: comments.map((comment) => ({
            id: comment.id,
            content: comment.content,
            createdAt: comment.createdAt,
            user: {
              id: comment.userId,
              fullName: comment.fullName || "Unknown User",
              imageAva: comment.imageAva ? `/uploads/${comment.imageAva}` : null
            }
          }))
        };
      })
    );

    await connection.commit();
    res.status(200).json(formattedPosts);
  } catch (error) {
    if (connection) await connection.rollback();
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

// Lấy danh sách bài đăng theo id
const getPostById = async (req, res) => {
  let connection;

  try {
    console.log("URL được gọi:", req.originalUrl); // Log URL
    console.log("req.params:", req.params); // Log tham số

    // Bước 1: Lấy id từ tham số URL
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ message: "Thiếu ID bài đăng" });
    }

    const parsedPostId = parseInt(id, 10);
    if (isNaN(parsedPostId) || parsedPostId <= 0) {
      return res.status(400).json({ message: "ID bài đăng không hợp lệ" });
    }

    // Bước 2: Kiểm tra token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ message: "Không có token hoặc token không hợp lệ" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Token không được cung cấp" });
    }

    // Xác thực token
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    if (!decoded || !decoded.userId) {
      return res
        .status(401)
        .json({ message: "Token không hợp lệ hoặc đã hết hạn" });
    }

    // Bước 3: Kết nối cơ sở dữ liệu
    connection = await db.getConnection();
    if (!connection) {
      return res
        .status(500)
        .json({ message: "Không thể kết nối tới cơ sở dữ liệu" });
    }

    // Bước 4: Truy vấn bài đăng
    const [posts] = await connection.execute(
      "SELECT p.*, u.fullName, u.imageAva FROM posts p JOIN users u ON p.userId = u.id WHERE p.id = ?",
      [parsedPostId]
    );

    if (!posts || posts.length === 0) {
      return res.status(404).json({ message: "Không tìm thấy bài đăng" });
    }

    const post = posts[0];

    // Bước 5: Truy vấn danh sách lượt thích
    const [likes] = await connection.execute(
      "SELECT userId FROM likes WHERE postId = ?",
      [parsedPostId]
    );

    // Bước 6: Truy vấn danh sách bình luận
    const [comments] = await connection.execute(
      "SELECT c.*, u.fullName, u.imageAva FROM comments c LEFT JOIN users u ON c.userId = u.id WHERE c.postId = ? ORDER BY c.createdAt DESC",
      [parsedPostId]
    );

    // Bước 7: Định dạng dữ liệu trả về
    const formattedPost = {
      id: String(post.id), // Chuyển id thành chuỗi
      userId: post.userId,
      content: post.content,
      image: post.image ? `/uploads/${post.image}` : null,
      createdAt: post.createdAt,
      fullName: post.fullName || "Unknown User",
      imageAva: post.imageAva ? `/uploads/${post.imageAva}` : null,
      likes: likes.map((like) => ({
        userId: like.userId
      })),
      comments: comments.map((comment) => ({
        id: comment.id,
        content: comment.content,
        createdAt: comment.createdAt,
        user: {
          id: comment.userId,
          fullName: comment.fullName || "Unknown User",
          imageAva: comment.imageAva ? `/uploads/${comment.imageAva}` : null
        }
      }))
    };

    // Bước 8: Trả về kết quả
    return res.status(200).json(formattedPost);
  } catch (error) {
    console.error("Lỗi trong getPostById:", error.message);
    console.error("Chi tiết lỗi:", error.stack);

    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res
        .status(401)
        .json({ message: "Token không hợp lệ hoặc đã hết hạn" });
    }

    if (error.code === "ER_NO_SUCH_TABLE") {
      return res
        .status(500)
        .json({ message: "Bảng không tồn tại trong cơ sở dữ liệu" });
    }

    if (error.code === "ER_BAD_FIELD_ERROR") {
      return res.status(500).json({ message: "Cột không tồn tại trong bảng" });
    }

    return res
      .status(500)
      .json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) {
      connection.release();
      console.log("Đã giải phóng kết nối cơ sở dữ liệu");
    }
  }
};

// Lấy danh sách bài đăng của một người dùng cụ thể theo authorId
const getPostsByAuthor = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  const { authorId } = req.params;
  const offset = parseInt(req.query.offset, 10) || 0;
  const limit = parseInt(req.query.limit, 10) || 10;

  let connection;

  try {
    // Xác thực token
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const parsedAuthorId = parseInt(authorId, 10);
    if (isNaN(parsedAuthorId) || parsedAuthorId <= 0) {
      return res.status(400).json({ message: "ID tác giả không hợp lệ" });
    }

    // Kiểm tra kiểu dữ liệu
    if (isNaN(offset) || isNaN(limit) || offset < 0 || limit <= 0) {
      return res
        .status(400)
        .json({ message: "Tham số offset hoặc limit không hợp lệ" });
    }

    console.log("Parameters for posts query:", {
      parsedAuthorId,
      limit,
      offset
    });

    connection = await db.getConnection();

    // Lấy tổng số bài đăng
    const [totalResult] = await connection.execute(
      "SELECT COUNT(*) as total FROM posts WHERE userId = ?",
      [parsedAuthorId]
    );
    const total = totalResult[0].total;

    // Lấy danh sách bài đăng (truyền LIMIT và OFFSET trực tiếp)
    const [posts] = await connection.execute(
      `
      SELECT p.*, u.fullName, u.imageAva 
      FROM posts p 
      JOIN users u ON p.userId = u.id 
      WHERE p.userId = ?
      ORDER BY p.createdAt DESC
      LIMIT ${connection.escape(limit)} OFFSET ${connection.escape(offset)}
      `,
      [parsedAuthorId]
    );

    // Lấy lượt thích và bình luận
    const formattedPosts = await Promise.all(
      posts.map(async (post) => {
        try {
          const [likes] = await connection.execute(
            "SELECT userId FROM likes WHERE postId = ?",
            [post.id]
          );

          const [comments] = await connection.execute(
            `
            SELECT c.*, u.fullName, u.imageAva 
            FROM comments c 
            LEFT JOIN users u ON c.userId = u.id 
            WHERE c.postId = ? 
            ORDER BY c.createdAt DESC
            `,
            [post.id]
          );

          return {
            ...post,
            image: post.image ? `/uploads/${post.image}` : null,
            imageAva: post.imageAva ? `/uploads/${post.imageAva}` : null,
            likes: likes.map((like) => ({ userId: like.userId })),
            comments: comments.map((comment) => ({
              id: comment.id,
              content: comment.content,
              createdAt: comment.createdAt,
              user: {
                id: comment.userId,
                fullName: comment.fullName || "Unknown User",
                imageAva: comment.imageAva
                  ? `/uploads/${comment.imageAva}`
                  : null
              }
            }))
          };
        } catch (error) {
          console.error(`Error processing post ${post.id}:`, error);
          return null;
        }
      })
    ).then((results) => results.filter((result) => result !== null));

    res.status(200).json({
      posts: formattedPosts,
      offset,
      limit,
      total
    });
  } catch (error) {
    console.error("Error in getPostsByAuthor:", error);
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
    // console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId;
    // console.log("Step 2 - Current user ID:", currentUserId);

    const { searchQuery } = req.params;
    const limit = parseInt(req.query.limit, 10) || 10;
    const offset = parseInt(req.query.offset, 10) || 0;
    // console.log("Step 3 - Search params:", { searchQuery, limit, offset });

    if (!searchQuery) {
      // console.log("searchQuery is required");
      return res.status(400).json({ message: "searchQuery là bắt buộc" });
    }
    if (isNaN(limit) || isNaN(offset) || limit < 0 || offset < 0) {
      // console.log("Invalid limit or offset");
      return res
        .status(400)
        .json({ message: "Limit và offset phải là số nguyên không âm" });
    }

    // console.log("Step 4 - Get database connection");
    connection = await db.getConnection();
    // console.log("Step 4.1 - Check current database");
    const [dbCheck] = await connection.execute("SELECT DATABASE() as db");
    // console.log("Step 4.2 - Current database:", dbCheck[0].db);

    // console.log("Step 5 - Count total users");
    const [totalResult] = await connection.execute(
      "SELECT COUNT(*) as total FROM users WHERE fullName LIKE ? AND id != ?",
      [`%${searchQuery}%`, currentUserId]
    );
    const total = totalResult[0].total;
    // console.log("Step 6 - Total users:", total);

    // console.log("Step 7 - Search users");
    const usersQuery = `SELECT id, fullName, imageAva, imagePublicId FROM users WHERE fullName LIKE ? AND id != ? ORDER BY fullName ASC LIMIT ${limit} OFFSET ${offset}`;
    // console.log("Step 7.1 - Users query:", usersQuery);
    // console.log("Step 7.2 - Users params:", [
    //   `%${searchQuery}%`,
    //   currentUserId
    // ]);
    const [users] = await connection.query(usersQuery, [
      `%${searchQuery}%`,
      currentUserId
    ]);
    // console.log("Step 8 - Found users:", users);

    const userIds = users.map((user) => parseInt(user.id, 10));
    // console.log("Step 9 - User IDs:", userIds);

    let friends = [];
    let sentRequests = [];
    let receivedRequests = [];

    if (userIds.length > 0) {
      // console.log("Step 10 - Check friends");
      const [friendRows] = await connection.execute(
        "SELECT userId, friendId FROM friends WHERE (userId = ? AND friendId IN (" +
          userIds.map(() => "?").join(",") +
          ")) OR (friendId = ? AND userId IN (" +
          userIds.map(() => "?").join(",") +
          "))",
        [currentUserId, ...userIds, currentUserId, ...userIds]
      );
      friends = friendRows;
      // console.log("Step 11 - Friends:", friends);

      // console.log("Step 12 - Check sent friend requests");
      // console.log("Step 12.1 - Query params:", {
      //   currentUserId: currentUserId,
      //   userIds: userIds
      // });
      const sentQuery =
        "SELECT senderId, receiverId FROM friend_requests WHERE senderId = ? AND receiverId IN (" +
        userIds.map(() => "?").join(",") +
        ") AND status = ?";
      // console.log("Step 12.2 - Sent query:", sentQuery);
      // console.log("Step 12.3 - Query values:", [
      //   currentUserId,
      //   ...userIds,
      //   "pending"
      // ]);
      const [sentRows] = await connection.execute(sentQuery, [
        currentUserId,
        ...userIds,
        "pending"
      ]);
      sentRequests = sentRows;
      // console.log("Step 13 - Sent requests:", sentRequests);
      // console.log(
      //   "Step 13.1 - Sent requests map:",
      //   sentRequests.map((req) => req.receiverId)
      // );

      // console.log("Step 14 - Check received friend requests");
      const receivedQuery =
        "SELECT senderId, receiverId FROM friend_requests WHERE receiverId = ? AND senderId IN (" +
        userIds.map(() => "?").join(",") +
        ") AND status = ?";
      // console.log("Step 14.1 - Received query:", receivedQuery);
      const [receivedRows] = await connection.execute(receivedQuery, [
        currentUserId,
        ...userIds,
        "pending"
      ]);
      receivedRequests = receivedRows;
      // console.log("Step 15 - Received requests:", receivedRequests);
    } else {
      // console.log("Step 10 - No user IDs, skipping relationship checks");
    }

    const friendsMap = new Set();
    friends.forEach((friend) => {
      if (friend.userId === currentUserId) {
        friendsMap.add(friend.friendId);
      } else if (friend.friendId === currentUserId) {
        friendsMap.add(friend.userId);
      }
    });
    // console.log("Step 15.1 - Friends map:", Array.from(friendsMap));

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

    // console.log("Step 16 - Formatted users:", formattedUsers);

    res.status(200).json({
      total,
      offset,
      limit,
      users: formattedUsers
    });
  } catch (error) {
    // console.error("Lỗi tìm kiếm người dùng:", {
    //   error: error.message,
    //   stack: error.stack
    // });
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
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
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

    console.log("Step 8 - Send friend request");
    const [result] = await connection.execute(
      "INSERT INTO friend_requests (senderId, receiverId, status, createdAt, updatedAt) VALUES (?, ?, 'pending', NOW(), NOW())",
      [currentUserId, friendIdNum]
    );

    // Lấy thông tin người gửi để gửi kèm thông báo
    const [sender] = await connection.execute(
      "SELECT fullName, imageAva FROM users WHERE id = ?",
      [currentUserId]
    );

    // Phát sự kiện qua Socket.IO tới người nhận (friendId)
    const friendIdStr = friendIdNum.toString();
    console.log(
      `Step 9 - Emitting receive-friend-request to user ${friendIdStr}`
    );
    if (req.io) {
      const eventData = {
        senderId: currentUserId.toString(),
        fullName: sender[0].fullName,
        image: sender[0].imageAva ? `/uploads/${sender[0].imageAva}` : null
      };
      console.log("Event data being emitted:", eventData);
      req.io.to(friendIdStr).emit("receive-friend-request", eventData);
    } else {
      console.error("Socket.IO: req.io is not available");
    }

    console.log("Step 10 - Friend request sent successfully");
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
    // console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId;
    // console.log("Step 2 - Current user ID:", currentUserId);

    // console.log("Step 3 - Get database connection");
    connection = await db.getConnection();

    // console.log("Step 3.1 - Check current database");
    const [dbCheck] = await connection.execute("SELECT DATABASE() as db");
    // console.log("Step 3.2 - Current database:", dbCheck[0].db);

    // console.log("Step 4 - Fetch pending friend requests");
    const query = `
      SELECT fr.id, fr.senderId, fr.receiverId, fr.createdAt,
             u.id AS userId, u.fullName, u.imageAva
      FROM friend_requests fr
      JOIN users u ON fr.senderId = u.id
      WHERE fr.receiverId = ? AND fr.status = 'pending' AND fr.senderId != ?
      ORDER BY fr.createdAt DESC
    `;
    // console.log("Step 4.1 - Query:", query);
    // console.log("Step 4.2 - Query params:", [currentUserId, currentUserId]);
    const [requestRows] = await connection.execute(query, [
      currentUserId,
      currentUserId
    ]);
    // console.log("Step 5 - Pending requests:", requestRows);

    if (requestRows.length === 0) {
      // console.log(
      //   "Step 5.3 - No pending friend requests found for receiverId:",
      //   currentUserId
      // );
    } else {
      // console.log("Step 5.1 - Verify receiverId and senderId in results");
      const invalidRequests = requestRows.filter(
        (request) =>
          request.receiverId !== currentUserId ||
          request.senderId === currentUserId
      );
      if (invalidRequests.length > 0) {
        // console.error("Step 5.2 - Found invalid requests:", invalidRequests);
        throw new Error(
          "Truy vấn trả về dữ liệu không hợp lệ: receiverId không khớp hoặc senderId trùng với currentUserId"
        );
      }
    }

    const formattedRequests = requestRows.map((request) => ({
      id: request.id.toString(),
      sender: {
        id: request.userId.toString(),
        fullName: request.fullName,
        image: request.imageAva ? `/uploads/${request.imageAva}` : null
      },
      createdAt: new Date(request.createdAt).toISOString()
    }));

    // console.log("Step 6 - Formatted pending requests:", formattedRequests);
    res.status(200).json(formattedRequests);
  } catch (error) {
    // console.error("Lỗi lấy danh sách yêu cầu kết bạn đang chờ:", {
    //   error: error.message,
    //   stack: error.stack
    // });
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

// Chấp nhận yêu cầu kết bạn
const acceptFriendRequest = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId;
    // console.log("Step 2 - Current user ID:", currentUserId);

    const { friendId } = req.body;
    // console.log("Step 3 - Friend ID:", friendId);

    if (!friendId) {
      // console.log("friendId is required");
      return res.status(400).json({ message: "friendId là bắt buộc" });
    }

    const friendIdNum = parseInt(friendId, 10);
    if (isNaN(friendIdNum)) {
      // console.log("Invalid friendId");
      return res.status(400).json({ message: "friendId không hợp lệ" });
    }

    if (friendIdNum === currentUserId) {
      // console.log("Cannot accept friend request from yourself");
      return res
        .status(400)
        .json({ message: "Không thể chấp nhận yêu cầu kết bạn từ chính mình" });
    }

    // console.log("Step 4 - Get database connection");
    connection = await db.getConnection();

    // console.log("Step 5 - Check if friendId exists");
    const [friendRows] = await connection.execute(
      "SELECT id, fullName, imageAva FROM users WHERE id = ?",
      [friendIdNum]
    );
    if (friendRows.length === 0) {
      // console.log("Friend not found");
      return res.status(400).json({ message: "Người dùng không tồn tại" });
    }

    // console.log("Step 6 - Check if already friends");
    const [friendshipRows] = await connection.execute(
      "SELECT * FROM friends WHERE (userId = ? AND friendId = ?) OR (userId = ? AND friendId = ?)",
      [currentUserId, friendIdNum, friendIdNum, currentUserId]
    );
    if (friendshipRows.length > 0) {
      // console.log("Already friends");
      return res.status(400).json({ message: "Hai người đã là bạn bè" });
    }

    // console.log("Step 7 - Check if friend request exists");
    const [requestRows] = await connection.execute(
      "SELECT * FROM friend_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
      [friendIdNum, currentUserId]
    );
    if (requestRows.length === 0) {
      // console.log("Friend request not found or not pending");
      return res.status(400).json({
        message: "Yêu cầu kết bạn không tồn tại hoặc không ở trạng thái chờ"
      });
    }

    const friendRequest = requestRows[0];
    // console.log("Step 8 - Friend request found:", friendRequest);

    // console.log("Step 9 - Begin transaction to accept friend request");
    await connection.beginTransaction();

    // console.log("Step 10 - Add friendship to friends table");
    await connection.execute(
      "INSERT INTO friends (userId, friendId, createdAt) VALUES (?, ?, NOW()), (?, ?, NOW())",
      [currentUserId, friendIdNum, friendIdNum, currentUserId]
    );

    // console.log("Step 11 - Delete friend request from friend_requests table");
    await connection.execute("DELETE FROM friend_requests WHERE id = ?", [
      friendRequest.id
    ]);

    await connection.commit();
    // console.log("Step 12 - Transaction committed successfully");

    // console.log("Step 13 - Friend request accepted successfully");
    res.status(200).json({ message: "Friend request accepted successfully." });
  } catch (error) {
    if (connection) {
      await connection.rollback();
      // console.log("Step 14 - Transaction rolled back due to error");
    }
    // console.error("Lỗi chấp nhận yêu cầu kết bạn:", {
    //   error: error.message,
    //   stack: error.stack
    // });
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

// Hủy yêu cầu kết bạn
const cancelFriendRequest = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // console.log("Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;
  try {
    // console.log("Step 1 - Verify token");
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const currentUserId = decoded.userId;
    // console.log("Step 2 - Current user ID:", currentUserId);

    const { friendId } = req.body;
    // console.log("Step 3 - Friend ID:", friendId);

    if (!friendId) {
      // console.log("friendId is required");
      return res.status(400).json({ message: "friendId là bắt buộc" });
    }

    const friendIdNum = parseInt(friendId, 10);
    if (isNaN(friendIdNum)) {
      // console.log("Invalid friendId");
      return res.status(400).json({ message: "friendId không hợp lệ" });
    }

    if (friendIdNum === currentUserId) {
      // console.log("Cannot cancel friend request to yourself");
      return res
        .status(400)
        .json({ message: "Không thể hủy yêu cầu kết bạn với chính mình" });
    }

    // console.log("Step 4 - Get database connection");
    connection = await db.getConnection();

    // console.log("Step 5 - Check if friendId exists");
    const [friendRows] = await connection.execute(
      "SELECT id, fullName, imageAva FROM users WHERE id = ?",
      [friendIdNum]
    );
    if (friendRows.length === 0) {
      // console.log("Friend not found");
      return res.status(400).json({ message: "Người dùng không tồn tại" });
    }

    // console.log("Step 6 - Check if friend request exists");
    const [requestRows] = await connection.execute(
      "SELECT * FROM friend_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
      [friendIdNum, currentUserId]
    );
    if (requestRows.length === 0) {
      // console.log("Friend request not found or not pending");
      return res.status(400).json({
        message: "Yêu cầu kết bạn không tồn tại hoặc không ở trạng thái chờ"
      });
    }

    console.log("Step 7 - Friend requests found:", requestRows);

    console.log(
      "Step 8 - Delete all matching friend requests from friend_requests table"
    );
    const [deleteResult] = await connection.execute(
      "DELETE FROM friend_requests WHERE senderId = ? AND receiverId = ? AND status = 'pending'",
      [friendIdNum, currentUserId]
    );
    console.log("Step 8.1 - Delete result:", deleteResult);
    if (deleteResult.affectedRows === 0) {
      console.log(
        "No rows deleted, friend request may have already been removed"
      );
      return res.status(400).json({
        message:
          "Không thể xóa yêu cầu kết bạn, có thể yêu cầu đã bị xóa trước đó"
      });
    }

    // console.log("Step 9 - Friend request canceled successfully");
    res.status(200).json({ message: "Friend request canceled successfully." });
  } catch (error) {
    // console.error("Lỗi hủy yêu cầu kết bạn:", {
    //   error: error.message,
    //   stack: error.stack
    // });
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

// Lấy danh sách bạn bè
const getFriends = async (req, res) => {
  console.log("getFriends called with headers:", req.headers);

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  let connection;

  try {
    // Kiểm tra biến môi trường ACCESS_TOKEN_SECRET
    if (!process.env.ACCESS_TOKEN_SECRET) {
      throw new Error(
        "ACCESS_TOKEN_SECRET không được định nghĩa trong biến môi trường"
      );
    }

    // Xác thực token
    console.log("Verifying token...");
    console.log("Token:", token);
    console.log("ACCESS_TOKEN_SECRET:", process.env.ACCESS_TOKEN_SECRET);
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    console.log("Decoded token:", decoded);

    // Kiểm tra currentUserId
    const currentUserId = decoded.userId;
    console.log("Current user ID:", currentUserId);
    console.log("Type of currentUserId:", typeof currentUserId);
    const parsedUserId = parseInt(currentUserId, 10);
    console.log("Parsed user ID:", parsedUserId);
    if (isNaN(parsedUserId) || parsedUserId <= 0) {
      throw new Error("Invalid user ID in token: must be a positive number");
    }

    // Xử lý limit và offset
    const rawLimit = req.query.limit;
    const rawOffset = req.query.offset;
    console.log("Raw limit:", rawLimit, "Raw offset:", rawOffset);

    const limit = parseInt(rawLimit, 10) || 10;
    const offset = parseInt(rawOffset, 10) || 0;
    console.log("Parsed limit:", limit, "Parsed offset:", offset);
    console.log(
      "Type of limit:",
      typeof limit,
      "Type of offset:",
      typeof offset
    );

    if (isNaN(limit) || isNaN(offset) || limit < 0 || offset < 0) {
      return res
        .status(400)
        .json({ message: "Limit và offset phải là số nguyên không âm" });
    }

    // Đảm bảo limit và offset là số nguyên
    const safeLimit = Number(limit);
    const safeOffset = Number(offset);
    console.log("Safe limit:", safeLimit, "Safe offset:", safeOffset);
    console.log(
      "Type of safeLimit:",
      typeof safeLimit,
      "Type of safeOffset:",
      typeof safeOffset
    );

    // Kết nối cơ sở dữ liệu
    console.log("Attempting to get database connection...");
    connection = await db.getConnection();
    console.log("Database connection established");

    // Đếm tổng số bạn bè
    console.log("Executing total count query with userId:", parsedUserId);
    const [totalResult] = await connection.execute(
      "SELECT COUNT(*) as total FROM friends WHERE userId = ?",
      [parsedUserId]
    );
    console.log("Total result:", totalResult);

    if (!totalResult || !totalResult[0]) {
      throw new Error("Failed to retrieve total count of friends");
    }
    const total = totalResult[0].total;
    console.log("Total friends:", total);

    // Lấy danh sách bạn bè bằng connection.query
    console.log("Executing friends query with parameters:", [
      parsedUserId,
      safeLimit,
      safeOffset
    ]);
    const [friends] = await connection.query(
      `
      SELECT u.id, u.fullName, u.email, u.imageAva 
      FROM friends f 
      JOIN users u ON f.friendId = u.id 
      WHERE f.userId = ? 
      ORDER BY u.fullName ASC 
      LIMIT ? OFFSET ?
      `,
      [parsedUserId, safeLimit, safeOffset]
    );
    console.log("Friends result:", friends);

    // Xử lý trường hợp không có bạn bè
    if (!friends || friends.length === 0) {
      return res.status(200).json({
        total: 0,
        offset,
        limit,
        friends: []
      });
    }

    // Định dạng dữ liệu bạn bè
    console.log("Formatting friends data...");
    const formattedFriends = friends.map((friend) => {
      if (!friend || !friend.id) {
        throw new Error("Invalid friend data: missing id");
      }
      return {
        id: friend.id.toString(),
        fullName: friend.fullName || "Người dùng không xác định",
        email: friend.email || "",
        image: friend.imageAva ? `/uploads/${friend.imageAva}` : null
      };
    });
    console.log("Formatted friends:", formattedFriends);

    // Trả về kết quả
    res.status(200).json({
      total,
      offset,
      limit,
      friends: formattedFriends
    });
  } catch (error) {
    console.error("Error in getFriends:", error.message);
    console.error("Stack trace:", error.stack);
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    if (error.code === "ER_NO_SUCH_TABLE") {
      return res
        .status(500)
        .json({ message: "Bảng users không tồn tại trong cơ sở dữ liệu" });
    }
    if (error.code === "ER_BAD_FIELD_ERROR") {
      return res.status(500).json({
        message:
          "Cột không tồn tại trong bảng users. Vui lòng kiểm tra các cột: id, fullName, email, imageAva"
      });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) {
      connection.release();
      console.log("Database connection released");
    }
  }
};

// Like một bài đăng
const likePost = async (req, res) => {
  console.log(
    "LikePost - Request received:",
    req.params,
    req.headers.authorization
  ); // Log để debug

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.log("LikePost - Missing or invalid Authorization header");
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  const { postId } = req.params;
  let connection;

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;
    const parsedPostId = parseInt(postId, 10);

    console.log(
      "LikePost - userId:",
      userId,
      "postId:",
      postId,
      "parsedPostId:",
      parsedPostId
    );

    if (isNaN(parsedPostId) || parsedPostId <= 0) {
      console.log("LikePost - Invalid postId");
      return res.status(400).json({ message: "ID bài đăng không hợp lệ" });
    }

    connection = await db.getConnection();

    const [postResult] = await connection.execute(
      "SELECT id FROM posts WHERE id = ?",
      [parsedPostId]
    );
    console.log("LikePost - Post query result:", postResult);

    if (postResult.length === 0) {
      console.log("LikePost - Post not found");
      return res.status(404).json({ message: "Bài đăng không tồn tại" });
    }

    const [likeResult] = await connection.execute(
      "SELECT id FROM likes WHERE userId = ? AND postId = ?",
      [userId, parsedPostId]
    );
    console.log("LikePost - Like query result:", likeResult);

    if (likeResult.length > 0) {
      console.log("LikePost - Already liked");
      return res.status(400).json({ message: "Bạn đã thích bài đăng này" });
    }

    await connection.execute(
      "INSERT INTO likes (userId, postId, createdAt) VALUES (?, ?, NOW())",
      [userId, parsedPostId]
    );

    console.log("LikePost - Like added successfully");
    res.status(201).json({ message: "Thích bài đăng thành công" });
  } catch (error) {
    console.error("Error in likePost:", error);
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

// Unlike một bài đăng
const unlikePost = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  const { postId } = req.params;
  let connection;

  try {
    // Xác thực token
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;
    const parsedPostId = parseInt(postId, 10);

    if (isNaN(parsedPostId) || parsedPostId <= 0) {
      return res.status(400).json({ message: "ID bài đăng không hợp lệ" });
    }

    connection = await db.getConnection();

    // Kiểm tra bài đăng có tồn tại không
    const [postResult] = await connection.execute(
      "SELECT id FROM posts WHERE id = ?",
      [parsedPostId]
    );
    if (postResult.length === 0) {
      return res.status(404).json({ message: "Bài đăng không tồn tại" });
    }

    // Kiểm tra xem người dùng đã thích bài đăng chưa
    const [likeResult] = await connection.execute(
      "SELECT id FROM likes WHERE userId = ? AND postId = ?",
      [userId, parsedPostId]
    );
    if (likeResult.length === 0) {
      return res.status(404).json({ message: "Bạn chưa thích bài đăng này" });
    }

    // Xóa lượt thích
    await connection.execute(
      "DELETE FROM likes WHERE userId = ? AND postId = ?",
      [userId, parsedPostId]
    );

    res.status(200).json({ message: "Bỏ thích bài đăng thành công" });
  } catch (error) {
    console.error("Error in unlikePost:", error);
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

// Thêm bình luận
const addComment = async (req, res) => {
  const { postId } = req.params;
  const { comment } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  if (!comment) {
    return res.status(400).json({ message: "Nội dung bình luận là bắt buộc" });
  }

  const token = authHeader.split(" ")[1];
  let connection;

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;

    connection = await db.getConnection();
    await connection.beginTransaction();

    // Thêm bình luận mới
    const [result] = await connection.execute(
      "INSERT INTO comments (userId, postId, content, createdAt) VALUES (?, ?, ?, NOW())",
      [userId, postId, comment]
    );

    // Lấy thông tin bình luận vừa thêm, bao gồm thông tin người dùng
    const [newComment] = await connection.execute(
      "SELECT c.*, u.fullName, u.imageAva " +
        "FROM comments c LEFT JOIN users u ON c.userId = u.id " + // Sử dụng LEFT JOIN
        "WHERE c.id = ?",
      [result.insertId]
    );

    if (newComment.length === 0) {
      throw new Error("Không tìm thấy bình luận vừa thêm");
    }

    const formattedComment = {
      id: newComment[0].id,
      content: newComment[0].content,
      createdAt: newComment[0].createdAt,
      user: {
        id: newComment[0].userId,
        fullName: newComment[0].fullName || "Unknown User", // Giá trị mặc định
        imageAva: newComment[0].imageAva
          ? `/uploads/${newComment[0].imageAva}`
          : null
      }
    };

    await connection.commit();
    res.status(200).json(formattedComment);
  } catch (error) {
    if (connection) await connection.rollback();
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

// Xóa bình luận
const deleteComment = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  const { postId, commentId } = req.params; // Lấy postId và commentId từ params
  let connection;

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;

    connection = await db.getConnection();
    await connection.beginTransaction();

    // Kiểm tra xem bài đăng có tồn tại không
    const [posts] = await connection.execute(
      "SELECT * FROM posts WHERE id = ?",
      [postId]
    );
    if (posts.length === 0) {
      return res.status(404).json({ message: "Bài đăng không tồn tại" });
    }

    // Kiểm tra xem bình luận có tồn tại và thuộc về người dùng không
    const [comments] = await connection.execute(
      "SELECT * FROM comments WHERE id = ? AND postId = ? AND userId = ?",
      [commentId, postId, userId]
    );
    if (comments.length === 0) {
      return res.status(404).json({
        message: "Bình luận không tồn tại hoặc bạn không có quyền xóa"
      });
    }

    // Xóa bình luận
    await connection.execute("DELETE FROM comments WHERE id = ?", [commentId]);

    await connection.commit();
    res.status(200).json({ message: "Xóa bình luận thành công" });
  } catch (error) {
    if (connection) await connection.rollback();
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

// Lấy thông tin chi tiết người dùng theo id
const getUserById = async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log("Authorization header:", authHeader);
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Không được phép truy cập" });
  }

  const token = authHeader.split(" ")[1];
  const { id } = req.params;
  console.log("User ID from params:", id);
  let connection;

  try {
    console.log("Verifying token...");
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    console.log("Decoded token:", decoded);
    const parsedUserId = parseInt(id, 10);
    console.log("Parsed user ID:", parsedUserId);

    if (isNaN(parsedUserId) || parsedUserId <= 0) {
      return res.status(400).json({ message: "ID người dùng không hợp lệ" });
    }

    console.log("Connecting to database...");
    connection = await db.getConnection();
    console.log("Database connection established");

    console.log("Executing user query...");
    const [users] = await connection.execute(
      "SELECT id, fullName, email, imageAva, imagePublicId, createdAt, updatedAt FROM users WHERE id = ?",
      [parsedUserId]
    );
    console.log("Query result:", users);

    if (users.length === 0) {
      return res.status(404).json({ message: "Người dùng không tồn tại" });
    }

    const user = users[0];
    console.log("User found:", user);

    console.log("Executing friends count query...");
    const [friendsCount] = await connection.execute(
      "SELECT COUNT(*) as totalFriends FROM friends WHERE userId = ?",
      [parsedUserId]
    );
    console.log("Friends count:", friendsCount);

    const formattedUser = {
      id: user.id.toString(),
      fullName: user.fullName,
      email: user.email,
      totalFriends: friendsCount[0].totalFriends,
      avatar: user.imageAva ? `/uploads/${user.imageAva}` : null,
      imagePublicId: user.imagePublicId || null,
      createdAt: new Date(user.createdAt).toISOString(),
      updatedAt: new Date(user.updatedAt).toISOString()
    };

    res.status(200).json(formattedUser);
  } catch (error) {
    console.error("Error in getUserById:", error.message);
    console.error("Stack trace:", error.stack);
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      return res.status(401).json({ message: "Không được phép truy cập" });
    }
    res.status(500).json({ message: "Lỗi máy chủ", error: error.message });
  } finally {
    if (connection) connection.release();
    console.log("Database connection released");
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
  getPostsByAuthor,
  searchUsers,
  sendFriendRequest,
  getPendingFriendRequests,
  forgotPassword,
  resetPassword,
  changePassword,
  acceptFriendRequest,
  cancelFriendRequest,
  getFriends,
  getPostById,
  likePost,
  unlikePost,
  addComment,
  deleteComment,
  getUserById
};
