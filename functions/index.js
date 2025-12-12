import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import authRoutes from "./routes/authRoutes.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Firebase Admin
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

// Firestore reference
app.locals = {
  db: admin.firestore(),
  admin,
};

// FIXED ROUTE PREFIX
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("FitGru Backend running with Firebase OTP.");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔥 Server running on port ${PORT}`));
