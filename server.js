require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const authRoutes = require("./routes/authRoutes");

const app = express();
const port = 4010;

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
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
