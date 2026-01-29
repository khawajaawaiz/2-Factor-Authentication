import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const ALGORITHM = "aes-256-cbc";
const KEY = process.env.ENCRYPTION_KEY;
const IV = process.env.ENCRYPTION_IV;

export const encrypt = (text) => {
    if (!text) return "";
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(KEY), Buffer.from(IV));
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
};

export const decrypt = (encryptedText) => {
    if (!encryptedText) return "";
    try {
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(KEY), Buffer.from(IV));
        let decrypted = decipher.update(encryptedText, "hex", "utf8");
        decrypted += decipher.final("utf8");
        return decrypted;
    } catch (error) {
        console.error("Decryption failed:", error.message);
        return "";
    }
};
