import express from "express";
import crypto from "crypto";

const router = express.Router();

// Send OTP
router.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  const { db } = req.app.locals;

  if (!email) {
    return res.status(400).json({ success: false, message: "Email required" });
  }

  try {
    // 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // Expire after 3 mins
    const expiresAt = Date.now() + 3 * 60 * 1000;

    await db.collection("email_verifications").doc(email).set({
      email,
      otp,
      expiresAt,
    });

    return res.json({
      success: true,
      message: "OTP sent successfully (Firebase).",
      otp, // ❗ remove in production
    });
  } catch (err) {
    console.error("send-otp error:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
});

// Verify OTP
router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const { db, admin } = req.app.locals;

  if (!email || !otp) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const docRef = db.collection("email_verifications").doc(email);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(400).json({
        success: false,
        message: "No OTP request found for this email.",
      });
    }

    const data = doc.data();

    if (data.otp !== otp) {
      return res.status(401).json({ success: false, message: "Invalid OTP" });
    }

    if (Date.now() > data.expiresAt) {
      return res.status(401).json({ success: false, message: "OTP expired" });
    }

    // Auto-delete verification record
    await docRef.delete();

    // Create or find user
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch {
      userRecord = await admin.auth().createUser({
        email,
        emailVerified: true,
      });
    }

    // Keep only UID based doc
    await db.collection("users").doc(userRecord.uid).set(
      {
        email,
        verified: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    return res.json({
      success: true,
      message: "OTP verified successfully",
      uid: userRecord.uid,
    });
  } catch (err) {
    console.error("verify-otp error:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
});

export default router;
