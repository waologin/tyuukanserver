// server.js
'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const webpush = require('web-push');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

// 環境変数
const {
  PRIVATE_KEY_PEM,      // server RSA private key (PEM)
  JWT_PUBLIC_KEY_PEM,   // JWT 検証用公開鍵（RS256 の場合）
  JWT_SECRET,           // HS256 の場合
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY,
  DATABASE_URL
} = process.env;

if (!PRIVATE_KEY_PEM || !(JWT_PUBLIC_KEY_PEM || JWT_SECRET) || !VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY || !DATABASE_URL) {
  console.error('Required environment variables missing.');
  process.exit(1);
}

// PostgreSQL pool
const pool = new Pool({ connectionString: DATABASE_URL });

// web-push 設定
webpush.setVapidDetails(
  'mailto:admin@example.com',
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

// --- Helper: base64 <-> Buffer (URL-safe not assumed) ---
function b64ToBuf(s) {
  return Buffer.from(s, 'base64');
}
function bufToB64(buf) {
  return buf.toString('base64');
}

// --- Decrypt wrapped AES key with server RSA private key (RSA-OAEP/SHA-256) ---
function unwrapAesKey(wrappedB64) {
  const wrapped = b64ToBuf(wrappedB64);
  // privateDecrypt with OAEP + SHA-256
  const priv = PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
  const decrypted = crypto.privateDecrypt(
    {
      key: priv,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    wrapped
  );
  // decrypted is raw AES key (32 bytes expected for AES-256)
  return decrypted;
}

// --- Decrypt AES-GCM blob ---
function decryptAesGcm(aesKeyBuf, ivB64, cipherB64, authTagB64) {
  const iv = b64ToBuf(ivB64);
  const ciphertext = b64ToBuf(cipherB64);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyBuf, iv);
  if (authTagB64) {
    const tag = b64ToBuf(authTagB64);
    decipher.setAuthTag(tag);
  } else {
    // assume tag appended to ciphertext (client-side variant)
    // Node's GCM expects separate tag; if client appended last 16 bytes, split it
    // But here we require client to send tag separately for clarity.
  }

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

// --- Lookup push subscription for a user ---
async function getPushSubscription(recipientId) {
  const res = await pool.query('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = $1', [recipientId]);
  if (res.rowCount === 0) return null;
  const row = res.rows[0];
  return {
    endpoint: row.endpoint,
    keys: {
      p256dh: row.p256dh,
      auth: row.auth
    }
  };
}

// --- Store message metadata ---
async function storeMessageMeta({ senderId, recipientId, messageCiphertext, aesIv }) {
  const q = `
    INSERT INTO messages (sender_id, recipient_id, message_ciphertext, aes_iv, auth_verified, status, server_timestamp)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id;
  `;
  const serverTs = new Date();
  const params = [senderId, recipientId, messageCiphertext, aesIv, true, 'queued', serverTs];
  const res = await pool.query(q, params);
  return { id: res.rows[0].id, serverTimestamp: serverTs };
}

// --- Public key endpoint (clients fetch server public key) ---
app.get('/public-key', (req, res) => {
  // Optionally, serve a stored public key. For simplicity assume PRIVATE_KEY_PEM contains private key; derive public
  try {
    const priv = PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
    const keyObj = crypto.createPrivateKey({ key: priv, format: 'pem' });
    const pub = keyObj.export({ type: 'spki', format: 'pem' });
    res.type('text/plain').send(pub);
  } catch (err) {
    console.error('failed to derive public key', err);
    res.status(500).json({ error: 'internal' });
  }
});

/**
 * POST /messages
 * Body:
 * {
 *  senderId, recipientId, messageCiphertext,
 *  wrappedAuthKey, authBlob, authIv, authTag, clientTimestamp
 * }
 */
app.post('/messages', async (req, res) => {
  const body = req.body;
  const {
    senderId,
    recipientId,
    messageCiphertext,
    wrappedAuthKey,
    authBlob,
    authIv,
    authTag,
    clientTimestamp
  } = body;

  if (!senderId || !recipientId || !messageCiphertext || !wrappedAuthKey || !authBlob || !authIv) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    // 1) unwrap AES key
    const aesKeyBuf = unwrapAesKey(wrappedAuthKey);
    if (aesKeyBuf.length !== 32) {
      // Warn but continue attempt (maybe AES-128); but we assume AES-256
      console.warn('unexpected aes key length', aesKeyBuf.length);
    }

    // 2) decrypt authBlob to obtain JWT or auth payload
    const authPlain = decryptAesGcm(aesKeyBuf, authIv, authBlob, authTag);
    // authPlain expected to be JSON (e.g., { token: "..."} or JWT string). We'll treat it as either
    let jwtToken = authPlain;
    try {
      const parsed = JSON.parse(authPlain);
      if (parsed && parsed.token) jwtToken = parsed.token;
    } catch (e) {
      // not JSON, maybe raw JWT - ok
    }

    // 3) validate JWT (support RS256 or HS256 depending on env)
    let decoded = null;
    if (JWT_PUBLIC_KEY_PEM) {
      // RS256
      decoded = jwt.verify(jwtToken, JWT_PUBLIC_KEY_PEM.replace(/\\n/g, '\n'), { algorithms: ['RS256'] });
    } else if (JWT_SECRET) {
      decoded = jwt.verify(jwtToken, JWT_SECRET);
    } else {
      throw new Error('No JWT verification method configured');
    }
    // basic checks (exp, sub etc) are performed by jwt.verify. Additional checks:
    // - Ensure senderId matches token subject or claim
    if (decoded.sub && decoded.sub !== senderId) {
      console.warn('token sub mismatch', decoded.sub, '!=', senderId);
      // proceed or reject depending on policy. Here reject.
      return res.status(401).json({ error: 'invalid_token_subject' });
    }

    // 4) store metadata and create message id + timestamp
    const { id: messageId, serverTimestamp } = await storeMessageMeta({
      senderId,
      recipientId,
      messageCiphertext,
      aesIv: authIv
    });

    // 5) fetch recipient push subscription
    const pushSub = await getPushSubscription(recipientId);
    if (!pushSub) {
      // no subscription: return success but mark undeliverable
      await pool.query('UPDATE messages SET status = $1 WHERE id = $2', ['no-subscription', messageId]);
      return res.status(202).json({ message_id: messageId, status: 'no-subscription' });
    }

    // 6) prepare push payload (minimal). Sign serverTimestamp optionally.
    // For simplicity: send message_id and serverTimestamp
    const payload = JSON.stringify({
      message_id: messageId,
      serverTimestamp: serverTimestamp.toISOString()
    });

    // 7) send web-push (silent push)
    try {
      await webpush.sendNotification(pushSub, payload);
      await pool.query('UPDATE messages SET status = $1 WHERE id = $2', ['pushed', messageId]);
      return res.status(201).json({ message_id: messageId, status: 'pushed', serverTimestamp: serverTimestamp.toISOString() });
    } catch (pushErr) {
      console.error('web-push failed', pushErr);
      await pool.query('UPDATE messages SET status = $1 WHERE id = $2', ['push-failed', messageId]);
      return res.status(201).json({ message_id: messageId, status: 'push-failed' });
    }

  } catch (err) {
    console.error('message processing failed', err);
    return res.status(500).json({ error: 'processing_failed' });
  }
});

// Endpoint to register/update push subscription
app.post('/push-subscriptions', async (req, res) => {
  const { userId, subscription } = req.body;
  if (!userId || !subscription || !subscription.endpoint) return res.status(400).json({ error: 'invalid' });

  try {
    const p256dh = subscription.keys && subscription.keys.p256dh;
    const authKey = subscription.keys && subscription.keys.auth;
    await pool.query(`
      INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, updated_at)
      VALUES ($1, $2, $3, $4, now())
      ON CONFLICT (user_id) DO UPDATE SET endpoint = $2, p256dh = $3, auth = $4, updated_at = now();
    `, [userId, subscription.endpoint, p256dh, authKey]);

    res.status(201).json({ ok: true });
  } catch (e) {
    console.error('failed to save subscription', e);
    res.status(500).json({ error: 'db_failed' });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`relay server listening on ${PORT}`);
});
