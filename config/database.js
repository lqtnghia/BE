const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "root", // Thay bằng mật khẩu MySQL của bạn
  database: "social_network",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool
  .getConnection()
  .then(() => {
    console.log("Connected to MySQL with connection pool");
  })
  .catch((err) => {
    console.error("MySQL connection error:", err);
  });

module.exports = pool;
