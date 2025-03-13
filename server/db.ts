import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is not set");
}

// SQL client for Drizzle ORM
const queryClient = postgres(process.env.DATABASE_URL, {
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10, // Connection pool size
  idle_timeout: 30 // Idle connection timeout in seconds
});
export const db = drizzle(queryClient);

// For direct database access using postgres.js
export const sql = queryClient;
