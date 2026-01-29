import { Sequelize } from "sequelize";
import dotenv from "dotenv";

dotenv.config();

const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
        host: process.env.DB_HOST,
        dialect: "postgres",
        port: process.env.DB_PORT || 5432,
        logging: false, // Set to console.log if you want to see SQL queries
    }
);

const dbConnect = async () => {
    try {
        await sequelize.authenticate();
        console.log("PostgreSQL Connected successfully via Sequelize.");
        // Auto-sync disabled as requested for manual management
    } catch (error) {
        console.error("Unable to connect to the database:", error.message);
        process.exit(1);
    }
};

export { sequelize };
export default dbConnect;