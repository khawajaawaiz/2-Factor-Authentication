import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import dbConnect from "./config/dbConnect.js";
import authRoutes from "./routes/authRoutes.js";
import passport from "passport";
import cookieParser from "cookie-parser";
import "./config/passportConfig.js";

dotenv.config();
dbConnect();

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

app.use(passport.initialize());

app.use(express.static(path.join(__dirname, "../public")));

app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.listen(process.env.PORT || 7001, () => {
    console.log(`Server is running on port ${process.env.PORT || 7001}`);
    console.log(`Open http://localhost:${process.env.PORT || 7001} in your browser`);
});
