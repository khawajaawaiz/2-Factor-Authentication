import { DataTypes } from "sequelize";
import { sequelize } from "../config/dbConnect.js";

const User = sequelize.define("User", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    isMfaActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    },
    twofactorSecret: {
        type: DataTypes.TEXT, // Using TEXT for encrypted secrets as they might be long
    },
    refreshToken: {
        type: DataTypes.STRING,
    },
}, {
    timestamps: true,
});

export default User;
 

