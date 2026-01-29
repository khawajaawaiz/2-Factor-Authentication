import { DataTypes } from "sequelize";
import { sequelize } from "../config/dbConnect.js";

const Blacklist = sequelize.define("Blacklist", {
    token: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    // Sequelize adds createdAt by default with timestamps: true
}, {
    timestamps: true,
    updatedAt: false, // Only need createdAt for blacklisting
});

export default Blacklist;
