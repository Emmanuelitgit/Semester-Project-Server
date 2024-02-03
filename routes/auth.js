const express = require('express')
const auth = require("../controllers/auth")

const router = express.Router()

router.post("/register", auth.register)
router.post("/login", auth.login)
router.post("/logout", auth.logout)
router.post("/send-otp", auth.sendOtp)
router.post("/verify-otp", auth.verifyOtp);
router.post("/reset-password", auth.resetPassword)
router.get("/users", auth.getUsers);

module.exports = router