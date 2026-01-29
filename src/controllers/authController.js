import bcrypt from "bcrypt";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import Blacklist from "../models/Blacklist.js";
import { encrypt, decrypt } from "../utils/cryptoUtils.js";

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    path: "/",
};

const generateTokens = (user) => {
    const accessToken = jwt.sign(
        { id: user.id, username: user.username, isMfaActive: user.isMfaActive },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
        { id: user.id, username: user.username, isMfaActive: user.isMfaActive },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
    );

    return { accessToken, refreshToken };
};

const setAuthCookies = (res, accessToken, refreshToken) => {
    res.cookie("accessToken", accessToken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshToken", refreshToken, { ...cookieOptions, maxAge: 7 * 24 * 60 * 60 * 1000 });
};

const getAuthToken = (req) => {
    return req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];
};

export const register = async (req, res) => {
    try {
        const { username, password } = req.body;
        const existingUser = await User.findOne({ where: { username } });

        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            username: username,
            password: hashedPassword,
            isMfaActive: false,
        });
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Error registering user", message: error.message });
    }
};

export const login = async (req, res) => {
    if (!req.user) {
        return res.status(401).json({message: "Unauthorized"});
    }

    if (req.user.isMfaActive) {
        return res.status(200).json({ 
            message: "2FA required", 
            mfaRequired: true, 
            username: req.user.username,
            userId: req.user.id 
        });
    }
    
    const { accessToken, refreshToken } = generateTokens(req.user);

    req.user.refreshToken = refreshToken;
    await req.user.save();

    setAuthCookies(res, accessToken, refreshToken);

    res.status(200).json({ 
        message: "User logged in successfully",  
        username: req.user.username,
        isMfaActive: req.user.isMfaActive
     });
};

export const authStatus = async (req, res) => {
    const token = getAuthToken(req);
    if (!token) return res.status(200).json({ authenticated: false });

    try {
        const blacklisted = await Blacklist.findOne({ where: { token } });
        if (blacklisted) return res.status(200).json({ authenticated: false });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findByPk(decoded.id);

        if (!user) return res.status(200).json({ authenticated: false });

        res.status(200).json({
            authenticated: true,
            username: user.username,
            isMfaActive: user.isMfaActive
        });
    } catch (error) {
        res.status(200).json({ authenticated: false });
    }
};

export const logout = async (req, res) => {
    try {
        const token = getAuthToken(req);

        if (token) {
            await Blacklist.create({ token });
        }

        if (req.user && req.user.id) {
            req.user.refreshToken = null;
            await req.user.save();
        }

        res.clearCookie("accessToken", cookieOptions);
        res.clearCookie("refreshToken", cookieOptions);
        res.status(200).json({ message: "User logged out successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error logging out", error: error.message });
    }
};

export const refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({ message: "No refresh token provided" });

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        const user = await User.findByPk(decoded.id);
        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

        user.refreshToken = newRefreshToken;
        await user.save();

        setAuthCookies(res, accessToken, newRefreshToken);
        res.status(200).json({ message: "Token refreshed" });
    } catch (error) {
        res.status(403).json({ message: "Invalid refresh token" });
    }
};

export const setup2FA = async (req, res) => {
    try {
        const user = req.user; // Already fetched by middleware
        const secret = speakeasy.generateSecret();
        console.log("Setting up 2FA for:", user.username, "Secret (base32):", secret.base32);
        
        user.twofactorSecret = encrypt(secret.base32);
        user.isMfaActive = false; // Don't activate until verified
        await user.save();
        const url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: req.user.username,
            encoding: "base32",
        });

        const qrImageUrl = await qrcode.toDataURL(url);
        res.status(200).json({
            message: "2FA setup successfully",
            isMfaActive: user.isMfaActive,
            secret: secret.base32,
            qrCode: qrImageUrl,
        });

    } catch (error) {
        res.status(500).json({ error: "Error setting up 2FA", message: error.message });
    }
};

export const verify2FA = async (req, res) => {
    try {
        const { token, userId } = req.body;
        
        const targetUserId = (req.user && req.user.id) ? req.user.id : userId;
        
        if (!targetUserId) {
            return res.status(400).json({ message: "User identity required" });
        }

        const user = await User.findByPk(targetUserId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const verified = speakeasy.totp.verify({
            secret: decrypt(user.twofactorSecret),
            encoding: "base32",
            token,
            window: 1
        });

        if (verified) {
            console.log("2FA Verified successfully for:", user.username);
            user.isMfaActive = true; 
            
            const { accessToken, refreshToken } = generateTokens(user);

            user.refreshToken = refreshToken;
            await user.save();

            setAuthCookies(res, accessToken, refreshToken);

            res.status(200).json({ 
                message: "2FA successful", 
                username: user.username,
                isMfaActive: user.isMfaActive
            });
        } else {
            res.status(400).json({ message: "Invalid 2FA Token" });
        }
    } catch (error) {
        res.status(500).json({ message: "Error verifying 2FA", error: error.message });
    }
};

export const reset2FA = async (req, res) => {
    try {
        const { token } = req.body;
        const user = req.user; // Always a document from verifyToken now

        if (!user || !user.isMfaActive) {
            return res.status(400).json({ message: "2FA is not active" });
        }

        const verified = speakeasy.totp.verify({
            secret: decrypt(user.twofactorSecret),
            encoding: "base32",
            token,
            window: 1
        });

        if (!verified) {
            return res.status(400).json({ message: "Invalid 2FA token. Reset failed." });
        }

        user.twofactorSecret = "";
        user.isMfaActive = false;
        await user.save();

        res.status(200).json({ 
            message: "2FA reset successful",
            isMfaActive: false 
        });
        
    } catch (error) {
        res.status(500).json({error: "Error resetting 2FA", message: error.message})
    }
};
