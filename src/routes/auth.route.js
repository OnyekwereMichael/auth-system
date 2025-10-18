import express from 'express';
import { checkAuth, forgotPassword, login, logout, resetPassword, signup, verifyEmail } from '../controllers/auth.controllers.js';
import { verify } from 'crypto';
import { verifyToken } from '../middleware/VerifyToken.js';

const router = express.Router();

router.get('/get-user', verifyToken, checkAuth);
router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);

router.post("/verify-email", verifyEmail)
router.post("/forgot-password", forgotPassword)
router.post("/reset-password/:token", resetPassword)

export default router;