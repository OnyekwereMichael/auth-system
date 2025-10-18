import bcryptjs from "bcryptjs";
import crypto from "crypto";
import { generateVerificationToken } from "../utils/generateVerificationToken.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import { sendPasswordResetEmail, sendResetSuccessEmail, sendVerificationEmail, sendWelcomeEmail } from "../mailtrap/emails.js";
import { User } from "../models/user.model.js";

export const signup = async (req, res) => {
    const { email, password, name } = req.body;
    try {
        if (!email || !password || !name) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const userAlreadyExists = await User.findOne({ email });
        if (userAlreadyExists) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcryptjs.hash(password, 10);
        const verificationToken = generateVerificationToken();
        const user = new User({
            email,
            password: hashedPassword,
            name,
            verificationToken,
            verificationTokenExpires: Date.now() + 3600000 // 1 hour
        });
        await user.save();

        generateTokenAndSetCookie(res, user._id)
        sendVerificationEmail(user.email, user.verificationToken)
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: {
                ...user._doc,
                password: null,
            }
        })

    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
}

export const verifyEmail = async (req, res) => {
    const { code } = req.body;
    try {
        const user = await User.findOne({
            verificationToken: code,
            verificationTokenExpires: { $gt: Date.now() },
        })

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired verification code' });
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        await sendWelcomeEmail(user.email, user.name);
        res.status(200).json({ success: true, message: 'Email verified successfully' });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isPasswordValid = await bcryptjs.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        generateTokenAndSetCookie(res, user._id);
        user.lastLogin = new Date();
        await user.save();
        res.status(200).json({
            success: true,
            message: 'Login successful',
            user: {
                ...user._doc,
                password: null,
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
};

export const logout = (req, res) => {
    res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'None' });
    res.status(200).json({ success: true, message: 'Logged out successfully' });
};



export const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User with this email does not exist' });
        }

        const resetToken = crypto.randomBytes(20).toString("hex");
        const resetTokenExpires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = resetTokenExpires;


        await user.save();

        await sendPasswordResetEmail(user.email, `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`);
        res.status(200).json({ success: true, message: 'Password reset email sent' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}

export const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired password reset token' });
        }
        user.password = await bcryptjs.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        sendResetSuccessEmail(user.email);
        res.status(200).json({ success: true, message: 'Password has been reset successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}

export const checkAuth = async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}