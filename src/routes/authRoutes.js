const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const multer = require("multer");
const path = require("path");

// Cấu hình Multer để xử lý upload hình ảnh
const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 100 * 1024 * 1024 }
}).single("image");

router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.post("/verify-otp", authController.verifyOTP);
router.post("/refresh-token", authController.refreshToken);
router.get("/auth-user", authController.getAuthUser);
router.post("/posts", authController.createPost(upload));
router.get("/posts", authController.getPosts);
router.get("/posts/author/:authorId", authController.getPostsByAuthor);
router.get("/posts/:id", authController.getPostById);
router.get("/search/users/:searchQuery", authController.searchUsers);
router.post("/friends/request", authController.sendFriendRequest);
router.get("/friends/pending", authController.getPendingFriendRequests);
router.post("/forgot-password", authController.forgotPassword);
router.post("/reset-password", authController.resetPassword);
router.post("/change-password", authController.changePassword);
router.post("/friends/accept", authController.acceptFriendRequest);
router.post("/friends/cancel", authController.cancelFriendRequest);
router.get("/friends", authController.getFriends);
router.post("/posts/:postId/like", authController.likePost);
router.delete("/posts/:postId/like", authController.unlikePost);
router.post("/posts/:postId/comment", authController.addComment);
router.delete(
  "/posts/:postId/comment/:commentId",
  authController.deleteComment
);
router.get("/users/:id", authController.getUserById);
router.get("/messages", authController.getMessages);
router.post("/messages/create", authController.createMessage);
router.get("/messages/conversations", authController.getConversations);
router.put("/messages/update-seen", authController.markMessagesAsSeen);
router.get("/messages/unread-count", authController.getUnreadCount);

module.exports = router;
