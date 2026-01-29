import {Router} from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import Blacklist from "../models/Blacklist.js";
import { register, login, authStatus, logout, setup2FA, verify2FA, reset2FA, refreshToken } from "../controllers/authController.js";

const router = Router();

const verifyToken = async (req, res, next) => {
    const token = req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: "Not authorized, no token" });

    try {
        const blacklisted = await Blacklist.findOne({ where: { token } });
        if (blacklisted) return res.status(401).json({ message: "Token is blacklisted" });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findByPk(decoded.id || decoded._id);
        
        if (!user) return res.status(401).json({ message: "User no longer exists" });

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: "Not authorized, token failed" });
    }
};

router.post("/register", register);

router.post("/login", (req, res, next) => {
    passport.authenticate("local", { session: false }, (err, user, info) => {
        if (err || !user) return res.status(400).json({ message: info?.message || "Login failed" });
        req.user = user;
        next();
    })(req, res, next);
}, login);

router.get("/status", authStatus);

router.post("/logout", verifyToken, logout);

router.post("/refresh", refreshToken);

router.post("/2fa/setup", verifyToken, setup2FA);

router.post("/2fa/verify", (req, res, next) => {
    const hasToken = req.cookies?.accessToken || req.headers.authorization;
    if (hasToken) return verifyToken(req, res, next);
    next();
}, verify2FA);

router.post("/2fa/reset", verifyToken, reset2FA);

export default router;
