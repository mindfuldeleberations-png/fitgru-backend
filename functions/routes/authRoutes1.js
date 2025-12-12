import express from "express";
import bcrypt from "bcryptjs";

const router = express.Router();

const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// ------------------- SEND VERIFICATION CODE -------------------
router.post("/sendVerificationCode", async (req, res) => {
  const { db, sgMail, admin } = req.app.locals;

  try {
    const { email, deviceId } = req.body;
    if (!email || !deviceId) return res.status(400).json({ error: "Missing email or deviceId" });

    const code = generateCode();
    const hashedCode = await bcrypt.hash(code, 10);
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000);

    // Delete old verification records
    const oldQ = await db.collection("email_verifications")
      .where("email", "==", email)
      .where("deviceId", "==", deviceId)
      .get();
    const batch = db.batch();
    oldQ.forEach(d => batch.delete(d.ref));
    if (!oldQ.empty) await batch.commit();

    // Create new verification record
    await db.collection("email_verifications").add({
      email, deviceId, hashedCode, expiresAt, createdAt: admin.firestore.FieldValue.serverTimestamp(), attempts: 0
    });

    res.json({ success: true });

    // Async email send
    const msg = {
      to: email,
      from: { email: process.env.SENDGRID_SENDER, name: "FitGru Team" },
      subject: "Your FitGru Verification Code",
      html: `<p>Your verification code is <strong>${code}</strong>. It expires in 5 minutes.</p>`
    };
    sgMail.send(msg).catch(err => console.error("❌ SendGrid:", err.response?.body || err));

  } catch (err) {
    console.error("❌ /sendVerificationCode error:", err);
    return res.status(500).json({ error: "Failed to send code" });
  }
});

// ------------------- VERIFY CODE -------------------
router.post("/verifyCode", async (req, res) => {
  const { db, admin } = req.app.locals;

  try {
    const { email, deviceId, code } = req.body;
    if (!email || !deviceId || !code) return res.status(400).json({ error: "Missing email, deviceId, or code" });

    const q = await db.collection("email_verifications")
      .where("email", "==", email)
      .where("deviceId", "==", deviceId)
      .orderBy("createdAt", "desc")
      .limit(1)
      .get();

    if (q.empty) return res.status(400).json({ error: "No verification record found." });

    const docSnap = q.docs[0];
    const data = docSnap.data();

    if (Date.now() > data.expiresAt.toMillis()) {
      await docSnap.ref.delete().catch(() => {});
      return res.status(400).json({ error: "Code expired" });
    }

    const isValid = await bcrypt.compare(code, data.hashedCode);
    if (!isValid) {
      await docSnap.ref.update({ attempts: (data.attempts || 0) + 1 });
      return res.status(400).json({ error: "Invalid code" });
    }

    await docSnap.ref.delete();
    return res.json({ success: true });

  } catch (err) {
    console.error("❌ /verifyCode error:", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

export default router;
