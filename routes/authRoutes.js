// routes/authRoutes.js
import express from "express";
import bcrypt from "bcryptjs";

const router = express.Router();

// Generate a 6-digit code
const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// ------------------- SEND VERIFICATION CODE -------------------
router.post("/sendVerificationCode", async (req, res) => {
  const { db, sgMail } = req.app.locals;
  try {
    const { email, deviceId } = req.body;
    if (!email || !deviceId) return res.status(400).json({ error: "Missing email or deviceId" });

    const code = generateCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = req.app.locals.admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000);

    const oldQ = await db.collection("email_verifications").where("email", "==", email).where("deviceId", "==", deviceId).get();
    const batch = db.batch();
    oldQ.forEach((d) => batch.delete(d.ref));
    if (!oldQ.empty) await batch.commit();

    await db.collection("email_verifications").add({
      email,
      deviceId,
      hashedCode,
      expiresAt,
      createdAt: req.app.locals.admin.firestore.FieldValue.serverTimestamp(),
      attempts: 0,
    });

    await sgMail.send({
      to: email,
      from: process.env.SENDGRID_SENDER,
      subject: "Your FitGru Verification Code",
      text: `Your FitGru verification code is ${code}. It expires in 5 minutes.`,
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("❌ /auth/sendVerificationCode error:", err);
    return res.status(500).json({ error: "Failed to send code" });
  }
});

// ------------------- VERIFY CODE -------------------
router.post("/verifyCode", async (req, res) => {
  const { admin, db } = req.app.locals;
  try {
    const { email, deviceId, code } = req.body;
    if (!email || !deviceId || !code) return res.status(400).json({ error: "Missing email, deviceId, or code" });

    const q = await db
      .collection("email_verifications")
      .where("email", "==", email)
      .where("deviceId", "==", deviceId)
      .orderBy("createdAt", "desc")
      .limit(1)
      .get();

    if (q.empty) return res.status(400).json({ error: "Verification record not found" });

    const docSnap = q.docs[0];
    const data = docSnap.data();

    if (Date.now() > data.expiresAt.toMillis()) {
      await docSnap.ref.delete();
      return res.status(400).json({ error: "Code expired" });
    }

    const isValid = await bcrypt.compare(code, data.hashedCode);
    if (!isValid) {
      await docSnap.ref.update({ attempts: (data.attempts || 0) + 1 });
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    const userRef = db.collection("users").doc(email);
    const userSnap = await userRef.get();
    const now = Date.now();
    const oneDayMs = 24 * 60 * 60 * 1000;

    if (!userSnap.exists) {
      await userRef.set({
        email,
        registeredDeviceId: deviceId,
        lastDeviceChangeAt: now,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } else {
      const user = userSnap.data();
      if (user.registeredDeviceId && user.registeredDeviceId !== deviceId) {
        const lastChange = user.lastDeviceChangeAt || 0;
        if (now - lastChange < oneDayMs) {
          const hoursLeft = Math.ceil((oneDayMs - (now - lastChange)) / (60 * 60 * 1000));
          return res.status(403).json({
            error: `Device can only be changed once every 24 hours. Try again in ~${hoursLeft} hour(s).`,
          });
        }
        await userRef.update({
          registeredDeviceId: deviceId,
          lastDeviceChangeAt: now,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      } else {
        await userRef.set({ email, registeredDeviceId: deviceId, lastDeviceChangeAt: user.lastDeviceChangeAt || now }, { merge: true });
      }
    }

    await docSnap.ref.delete();
    return res.json({ success: true });
  } catch (err) {
    console.error("❌ /auth/verifyCode error:", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

export default router;
