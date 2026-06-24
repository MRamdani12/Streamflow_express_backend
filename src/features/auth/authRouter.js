const express = require("express");
const authController = require("./authController");
const authenticateAccessToken = require("../../middlewares/authenticateAccessToken");

const router = express.Router();

router.post("/login", authController.login);
router.post("/register", authController.register);
router.post("/logout", authController.logout);
router.post("/refresh-token", authController.refreshToken);

// OAuth 2.0
// Google
router.get("/google", authController.googleLogin);
router.get("/google/callback", authController.googleCallback);

// Need to authenticate access token first before accessing user info
router.get("/me", authenticateAccessToken, authController.me);

module.exports = router;
