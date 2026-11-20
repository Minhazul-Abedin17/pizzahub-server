
import express from "express";
import "dotenv/config";
import cors from "cors";
import { connectToMongoDB } from "./config/db.js";

const app = express();
const PORT = process.env.PORT || 8000;
import menuRoutes from "./routes/menuRoutes.js";

app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));

app.use(express.json());

app.use("/api/menu-items", menuRoutes);

// MongoDB Connection
const db = await connectToMongoDB();
app.locals.db = db;

// Home Route
app.get("/", (req, res) => {
  res.send("PizzaHub Server is Running!");
});

// Health Check
app.get("/api/health", (req, res) => {
  res.send({
    success: true,
    message: "Server is healthy"
  });
});

app.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`);
});

export default app;
