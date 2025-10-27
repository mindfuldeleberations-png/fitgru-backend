// index.js — for Render backend, Firebase Auth + Firestore + SendGrid
import express from "express";
import admin from "firebase-admin";
import cors from "cors";
import dotenv from "dotenv";
import sgMail from "@sendgrid/mail";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Initialize Firebase Admin (Service Account JSON)
import serviceAccount from "./fitgru-app-firebase-adminsdk-fbsvc-ad36515dde.json" assert { type: "json" };

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();

// ✅ Setup SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ✅ Helper: Generate random 6-digit code
const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// ✅ POST /sendVerificationCode
app.post("/sendVerificationCode", async (req, res) => {
  try {
    const { email, deviceId } = req.body;

    if (!email || !deviceId) {
      return res.status(400).json({ error: "Email and deviceId are required" });
    }

    const code = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    // ✅ Store verification code in Firestore
    await db.collection("email_verifications").doc(email).set({
      email,
      deviceId,
      code,
      createdAt: new Date(),
      expiresAt,
    });

    // ✅ Send email via SendGrid
    const msg = {
      to: email,
      from: "no-reply@fitgru.com", // your verified sender
      subject: "Your FitnessGuru Verification Code",
      text: `Your verification code is: ${code}. It expires in 10 minutes.`,
    };
    await sgMail.send(msg);

    res.status(200).json({
      success: true,
      message: "Verification code sent successfully",
    });
  } catch (error) {
    console.error("Error sending verification code:", error);
    res.status(500).json({ error: "Failed to send verification code" });
  }
});

// ✅ POST /verifyCode
app.post("/verifyCode", async (req, res) => {
  try {
    const { email, deviceId, code } = req.body;
    if (!email || !deviceId || !code) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const docRef = db.collection("email_verifications").doc(email);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    const data = doc.data();

    if (data.code !== code) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    if (Date.now() > data.expiresAt) {
      return res.status(400).json({ error: "Code expired" });
    }

    // ✅ Check or create Firebase Auth user
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (err) {
      // Create user if not exist
      userRecord = await admin.auth().createUser({
        email,
        emailVerified: true,
        password: uuidv4(), // random
      });
    }

    // ✅ Mark email verified
    await admin.auth().updateUser(userRecord.uid, { emailVerified: true });

    // ✅ Optionally delete code after use
    await docRef.delete();

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    console.error("Verification failed:", error);
    res.status(500).json({ error: "Verification failed" });
  }
});

// ✅ Root endpoint for test
app.get("/", (req, res) => {
  res.send("✅ FitnessGuru backend is running.");
});

// ✅ Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
