-- 1. Tạo cơ sở dữ liệu
CREATE DATABASE social_media;
USE social_media;

-- 2. Tạo bảng users (bảng cha, cần tạo và chèn dữ liệu trước)
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    fullName VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    imageAv VARCHAR(255),
    imagePublicId VARCHAR(255),
    createdAt DATETIME NOT NULL,
    updatedAt DATETIME NOT NULL
);

-- Chèn dữ liệu mẫu vào bảng users
INSERT INTO users (id, fullName, email, password, imageAv, imagePublicId, createdAt, updatedAt) VALUES
(1, 'Lê Quang Trọng Nghĩa', 'lqtnghia2602@gmail.com', '$2b$10$jeWQTyQ9yLEauHC5GkeMS91eLtN...', NULL, NULL, '2025-03-22 08:44:08', '2025-03-29 02:27:57'),
(2, 'Nguyen Van A', 'nguyenvana@example.com', '$2a$10$examplehashedpassword', '/uploads/nguyenvana.jpg', 'profile-image-public-id-2', '2025-03-23 08:19:01', '2025-03-23 08:19:01'),
(3, 'Tran Thi B', 'tranthib@example.com', '$2a$10$examplehashedpassword', '/uploads/tranthib.jpg', 'profile-image-public-id-3', '2025-03-23 08:19:01', '2025-03-23 08:19:01'),
(4, 'Pham Van C', 'phamvanc@example.com', '$2a$10$examplehashedpassword', '/uploads/phamvanc.jpg', 'profile-image-public-id-4', '2025-03-23 08:19:01', '2025-03-23 08:19:01'),
(5, 'Nguyen Phuc Gia Bao', 'nguyenphucgiabao@example.com', '$2a$10$examplehashedpassword', '/uploads/nguyenphucgiabao.jpg', 'profile-image-public-id-5', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(6, 'Do Trong Khanh Hoang', 'dotrongkhanhhoang@example.com', '$2a$10$examplehashedpassword', '/uploads/dotrongkhanhhoang.jpg', 'profile-image-public-id-6', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(7, 'Vo Thi Bich Y', 'vothibichy@example.com', '$2a$10$examplehashedpassword', '/uploads/vothibichy.jpg', 'profile-image-public-id-7', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(8, 'Tran Danh Phuong', 'trandanhphuong@example.com', '$2a$10$examplehashedpassword', '/uploads/trandanhphuong.jpg', 'profile-image-public-id-8', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(9, 'Tran Duc Nam Phuong', 'tranducnamphuong@example.com', '$2a$10$examplehashedpassword', '/uploads/tranducnamphuong.jpg', 'profile-image-public-id-9', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(10, 'Vo Ba Thong', 'vobathong@example.com', '$2a$10$examplehashedpassword', '/uploads/vobathong.jpg', 'profile-image-public-id-10', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(11, 'Nguyen Gia Hung', 'nguyengiahung@example.com', '$2a$10$examplehashedpassword', '/uploads/nguyengiahung.jpg', 'profile-image-public-id-11', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(12, 'Nguyen Khoa Thuy Kinh', 'nguyenkhoathuykinh@example.com', '$2a$10$examplehashedpassword', '/uploads/nguyenkhoathuykinh.jpg', 'profile-image-public-id-12', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(13, 'Tran Thi Dao Tram', 'tranthidaotram@example.com', '$2a$10$examplehashedpassword', '/uploads/tranthidaotram.jpg', 'profile-image-public-id-13', '2025-03-23 14:13:37', '2025-03-23 14:13:37'),
(14, 'Nguyen Van An', 'nguyenvanan@gmail.com', '$2b$10$xlgY2o1vW2v3u4H5R6Y71B90oP1Q2...', NULL, NULL, '2024-01-15 10:00:00', '2024-01-15 10:00:00'),
(15, 'Tran Thi Bich Ngoc', 'tranthibichngoc@gmail.com', '$2b$10$xlgY2o1vW2v3u4H5R6Y71B90oP1Q2...', NULL, NULL, '2024-02-20 12:30:00', '2024-02-20 12:30:00'),
(19, 'User 19', 'user19@example.com', '$2a$10$examplehashedpassword', NULL, NULL, '2025-03-24 01:20:23', '2025-03-24 01:20:23'),
(22, 'User 22', 'user22@example.com', '$2a$10$examplehashedpassword', NULL, NULL, '2025-03-23 16:29:42', '2025-03-23 16:29:42'),
(25, 'User 25', 'user25@example.com', '$2a$10$examplehashedpassword', NULL, NULL, '2025-03-24 00:32:31', '2025-03-24 00:32:31'),
(27, 'User 27', 'user27@example.com', '$2a$10$examplehashedpassword', NULL, NULL, '2025-03-24 01:47:38', '2025-03-24 01:47:38'),
(41, 'User 41', 'user41@example.com', '$2a$10$examplehashedpassword', NULL, NULL, '2025-03-24 08:12:49', '2025-03-24 08:12:49'),
(42, 'User 42', 'user42@example.com', '$2a$10$examplehashedpassword', NULL, NULL, '2025-03-24 08:12:19', '2025-03-24 08:12:19');

-- 3. Tạo bảng posts (phụ thuộc vào bảng users)
CREATE TABLE posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content TEXT,
    userId INT NOT NULL,
    image VARCHAR(255),
    createdAt DATETIME NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
);

-- Chèn dữ liệu mẫu vào bảng posts
INSERT INTO posts (id, content, userId, image, createdAt) VALUES
(57, 'ttttttttttttttt', 1, NULL, '2025-04-07 01:37:06');

-- 4. Tạo bảng friend_requests (phụ thuộc vào bảng users)
CREATE TABLE friend_requests (
    id INT PRIMARY KEY AUTO_INCREMENT,
    senderId INT NOT NULL,
    receiverId INT NOT NULL,
    status ENUM('pending', 'accepted', 'rejected') NOT NULL,
    createdAt DATETIME NOT NULL,
    updatedAt DATETIME NOT NULL,
    FOREIGN KEY (senderId) REFERENCES users(id),
    FOREIGN KEY (receiverId) REFERENCES users(id)
);

-- Chèn dữ liệu mẫu vào bảng friend_requests
INSERT INTO friend_requests (id, senderId, receiverId, status, createdAt, updatedAt) VALUES
(1, 3, 4, 'pending', '2025-03-23 08:20:06', '2025-03-23 08:20:06'),
(2, 4, 1, 'pending', '2025-03-23 08:20:06', '2025-03-23 08:20:06'),
(3, 2, 3, 'rejected', '2025-03-23 08:20:06', '2025-03-23 08:20:06'),
(4, 5, 7, 'pending', '2025-03-23 14:14:03', '2025-03-23 14:14:03'),
(5, 6, 9, 'pending', '2025-03-23 14:14:03', '2025-03-23 14:14:03'),
(6, 10, 12, 'rejected', '2025-03-23 14:14:03', '2025-03-23 14:14:03'),
(15, 1, 7, 'pending', '2025-03-23 16:18:11', '2025-03-23 16:18:11'),
(16, 1, 10, 'pending', '2025-03-23 16:18:12', '2025-03-23 16:18:12'),
(22, 1, 19, 'pending', '2025-03-24 01:20:23', '2025-03-24 01:20:23'),
(23, 1, 27, 'pending', '2025-03-24 01:47:38', '2025-03-24 01:47:38'),
(24, 1, 42, 'pending', '2025-03-24 08:12:19', '2025-03-24 08:12:19'),
(25, 1, 41, 'pending', '2025-03-24 08:12:49', '2025-03-24 08:12:49'),
(31, 19, 1, 'pending', '2025-03-24 01:20:23', '2025-03-24 01:20:23'),
(32, 22, 1, 'pending', '2025-03-23 16:29:42', '2025-03-23 16:29:42'),
(33, 25, 1, 'pending', '2025-03-24 00:32:31', '2025-03-24 00:32:31'),
(34, 27, 1, 'pending', '2025-03-24 01:47:38', '2025-03-24 01:47:38');

-- 5. Tạo bảng friends (phụ thuộc vào bảng users)
CREATE TABLE friends (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT NOT NULL,
    friendId INT NOT NULL,
    createdAt DATETIME NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id),
    FOREIGN KEY (friendId) REFERENCES users(id)
);

-- Chèn dữ liệu mẫu vào bảng friends
INSERT INTO friends (id, userId, friendId, createdAt) VALUES
(1, 1, 2, '2025-03-23 08:19:34'),
(2, 1, 3, '2025-03-23 08:19:34'),
(3, 1, 4, '2025-03-23 08:19:34'),
(4, 1, 5, '2025-03-23 14:13:53'),
(5, 1, 11, '2025-03-23 14:13:53'),
(6, 2, 6, '2025-03-23 14:13:53'),
(7, 3, 8, '2025-03-23 14:13:53');

-- 6. Tạo bảng likes (phụ thuộc vào bảng posts và users)
CREATE TABLE likes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    postId INT NOT NULL,
    userId INT NOT NULL,
    createdAt DATETIME NOT NULL,
    FOREIGN KEY (postId) REFERENCES posts(id),
    FOREIGN KEY (userId) REFERENCES users(id)
);

-- 7. Tạo bảng otps (phụ thuộc vào bảng users)
CREATE TABLE otps (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT NOT NULL,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(10) NOT NULL,
    expiry DATETIME NOT NULL,
    createdAt DATETIME NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
);

-- Chèn dữ liệu mẫu vào bảng otps
INSERT INTO otps (id, userId, email, otp, expiry, createdAt) VALUES
(1, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 15:44:29', '2025-03-29 15:44:29', '2025-03-22 08:44:29'),
(2, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 16:08:57', '2025-03-29 16:08:57', '2025-03-22 09:08:56'),
(3, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 17:10:36', '2025-03-29 17:10:36', '2025-03-22 10:10:35'),
(4, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 17:11:04', '2025-03-29 17:11:04', '2025-03-22 10:11:03'),
(5, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 21:27:21', '2025-03-29 21:27:21', '2025-03-22 14:27:20'),
(6, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 21:27:58', '2025-03-29 21:27:58', '2025-03-22 14:27:58');

-- 8. Tạo bảng refresh_tokens (phụ thuộc vào bảng users)
CREATE TABLE refresh_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    userId INT NOT NULL,
    token TEXT NOT NULL,
    expiry DATETIME NOT NULL,
    createdAt DATETIME NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
);

-- Chèn dữ liệu mẫu vào bảng refresh_tokens
INSERT INTO refresh_tokens (id, userId, token, expiry, createdAt) VALUES
(1, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 15:44:29', '2025-03-22 08:44:29'),
(2, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 16:08:57', '2025-03-22 09:08:56'),
(3, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 17:10:36', '2025-03-22 10:10:35'),
(4, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 17:11:04', '2025-03-22 10:11:03'),
(5, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 21:27:21', '2025-03-22 14:27:20'),
(6, 1, 'eyJhbgOiU1z1N1tsInR5cC16kPXvC39_eyJc2...', '2025-03-29 21:27:58', '2025-03-22 14:27:58');

-- 9. Tạo bảng comments (phụ thuộc vào bảng posts và users)
CREATE TABLE comments (
    id INT PRIMARY KEY AUTO_INCREMENT,
    postId INT NOT NULL,
    userId INT NOT NULL,
    content TEXT NOT NULL,
    createdAt DATETIME NOT NULL,
    FOREIGN KEY (postId) REFERENCES posts(id),
    FOREIGN KEY (userId) REFERENCES users(id)
);