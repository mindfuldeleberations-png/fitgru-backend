// ===== Imports =====
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const sgMail = require("@sendgrid/mail");
const crypto = require("crypto");
const path = require("path");
const serviceAccount = require('./fitgru-app-firebase-adminsdk-fbsvc-ad36515dde.json');


// ===== Setup =====
const app = express();
app.use(cors());
app.use(express.json());

// Set your Firebase project ID
process.env.GOOGLE_CLOUD_PROJECT = "fitgru-app";


// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(
    path.join(__dirname, "fitgru-app-firebase-adminsdk-fbsvc-ad36515dde.json")
  ),
});

// ===== Config =====
const VERIF_COLLECTION = "email_verifications";
const VERIF_TTL_MINUTES = 15;
const MAX_SENDS_PER_HOUR = 5;
const MAX_ATTEMPTS = 5;

// SendGrid Setup
const sendgridKey = process.env.SENDGRID_API_KEY;
if (sendgridKey) {
  sgMail.setApiKey(sendgridKey);
} else {
  console.warn("⚠️ No SENDGRID_API_KEY found in environment — emails will not send.");
}

// ===== Helpers =====
function random6() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function docIdFor(email, deviceId) {
  return crypto.createHash("sha256").update(`${email}|${deviceId}`).digest("hex");
}

// ===== Endpoint: Send Verification Code =====
app.post("/sendVerificationCode", async (req, res) => {
  try {
    const { email, deviceId, label = "", platform = "" } = req.body;

    if (!email || !deviceId) {
      return res.status(400).json({ error: "Missing email or deviceId" });
    }

    const db = admin.firestore();

    // Rate limit: max 5 sends/hour
    const hourAgo = admin.firestore.Timestamp.fromMillis(Date.now() - 60 * 60 * 1000);
    const recent = await db
      .collection(VERIF_COLLECTION)
      .where("email", "==", email)
      .where("createdAt", ">=", hourAgo)
      .get();

    if (recent.size >= MAX_SENDS_PER_HOUR) {
      return res.status(429).json({ error: "Too many sends, try again later" });
    }

    const code = random6();
    const hashed = await bcrypt.hash(code, 10);
    const docId = docIdFor(email, deviceId);

    await db.collection(VERIF_COLLECTION).doc(docId).set({
      email,
      deviceId,
      label,
      platform,
      hashedCode: hashed,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(
        Date.now() + VERIF_TTL_MINUTES * 60 * 1000
      ),
      attempts: 0,
    });

    // Send email
    if (sendgridKey) {
      await sgMail.send({
        to: email,
        from: "no-reply@yourdomain.com",
        subject: "Your verification code",
        text: `Your code is ${code}. It expires in ${VERIF_TTL_MINUTES} minutes.`,
      });
    } else {
      console.log(`Generated code (not emailed): ${code}`);
    }

    res.json({ success: true, expiresInMinutes: VERIF_TTL_MINUTES });
  } catch (err) {
    console.error("Error in sendVerificationCode:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== Endpoint: Verify Code =====
app.post("/verifyCode", async (req, res) => {
  try {
    const { email, deviceId, code, label = "", platform = "" } = req.body;
    if (!email || !deviceId || !code)
      return res.status(400).json({ error: "Missing fields" });

    const db = admin.firestore();
    const docId = docIdFor(email, deviceId);
    const docRef = db.collection(VERIF_COLLECTION).doc(docId);

    const userRecord = await admin.auth().getUserByEmail(email);
    const uid = userRecord.uid;
    const userRef = db.collection("users").doc(uid);

    await db.runTransaction(async (txn) => {
      const snap = await txn.get(docRef);
      if (!snap.exists) throw new Error("no_verification");
      const v = snap.data();

      if (v.expiresAt && v.expiresAt.toMillis() < Date.now()) {
        txn.delete(docRef);
        throw new Error("expired");
      }

      if ((v.attempts || 0) >= MAX_ATTEMPTS)
        throw new Error("too_many_attempts");

      const match = await bcrypt.compare(code, v.hashedCode || "");
      if (!match) {
        txn.update(docRef, {
          attempts: admin.firestore.FieldValue.increment(1),
        });
        throw new Error("wrong_code");
      }

      const userSnap = await txn.get(userRef);
      const user = userSnap.exists ? userSnap.data() : {};
      const devices = user.devices || [];
      const deviceExists = devices.some((d) => d.deviceId === deviceId);

      const today = new Date().toISOString().slice(0, 10);
      const meta = user.deviceChangeMeta || { date: today, changesToday: 0 };
      const changesToday = meta.date === today ? meta.changesToday || 0 : 0;

      if (!deviceExists) {
        if (changesToday >= 1) throw new Error("device_change_limit");

        const newDevice = {
          deviceId,
          label,
          platform,
          verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          lastUsedAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        txn.set(
          userRef,
          {
            devices: admin.firestore.FieldValue.arrayUnion(newDevice),
            deviceChangeMeta: { date: today, changesToday: changesToday + 1 },
          },
          { merge: true }
        );
      } else {
        const updatedDevices = devices.map((d) =>
          d.deviceId === deviceId
            ? {
                ...d,
                verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
                lastUsedAt: admin.firestore.FieldValue.serverTimestamp(),
              }
            : d
        );
        txn.update(userRef, { devices: updatedDevices });
      }

      txn.delete(docRef);
    });

    res.json({ success: true, uid });
  } catch (err) {
    console.error("Error in verifyCode:", err);
    res.status(400).json({ error: err.message });
  }
});

// ===== Start Server =====
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
