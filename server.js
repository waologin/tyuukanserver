// server.js
'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const webpush = require('web-push');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const DB_FILE = process.env.DB_FILE || './db.json';
const PORT = process.env.PORT || 10000;

// env names from you
const PRIVATE_KEY_PEM_RAW = process.env.SERVER_PRIVKEY_CONTENTS || process.env.PRIVATE_KEY_PEM;
const VAPID_PUBLIC = process.env.VAPID_PUBLIC;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE;
const JWT_PUBLIC_KEY_PEM = process.env.JWT_PUBLIC_KEY_PEM;
const JWT_SECRET = process.env.JWT_SECRET;

if (!PRIVATE_KEY_PEM_RAW) {
  console.error('Missing SERVER_PRIVKEY_CONTENTS / PRIVATE_KEY_PEM env var');
  process.exit(1);
}
if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
  console.error('Missing VAPID_PUBLIC / VAPID_PRIVATE env var');
  process.exit(1);
}

// Convert literal "\n" sequences to actual newlines if necessary
const PRIVATE_KEY_PEM = PRIVATE_KEY_PEM_RAW.includes('\\n')
  ? PRIVATE_KEY_PEM_RAW.replace(/\\n/g, '\n')
  : PRIVATE_KEY_PEM_RAW;

// ensure DB file exists
function initDb() {
  if (!fs.existsSync(DB_FILE)) {
    const base = { push_subscriptions: {}, messages: {} };
    fs.writeFileSync(DB_FILE, JSON.stringify(base, null, 2));
  }
}
initDb();

function readDb() {
  const raw = fs.readFileSync(DB_FILE, 'utf8');
  return JSON.parse(raw);
}
function writeDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// simple ID generator (UUID v4-like)
function genId() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.randomBytes(1)[0] & 15 >> c / 4).toString(16)
  );
}

// configure web-push
webpush.setVapidDetails('mailto:admin@example.com', VAPID_PUBLIC, VAPID_PRIVATE);

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

// helpers
function b64ToBuf(s) { return Buffer.from(s, 'base64'); }
function bufToB64(b) { return Buffer.from(b).toString('base64'); }

// unwrap AES key (RSA-OAEP SHA-256)
function unwrapAesKey(wrappedB64) {
  const wrapped = b64ToBuf(wrappedB64);
  try {
    const decrypted = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY_PEM,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      wrapped
    );
    return decrypted; // Buffer
  } catch (err) {
    throw new Error('unwrap_failed:' + (err && err.message));
  }
}

// decrypt AES-GCM
function decryptAesGcm(aesKeyBuf, ivB64, cipherB64, authTagB64) {
  const iv = b64ToBuf(ivB64);
  let ciphertext = b64ToBuf(cipherB64);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyBuf, iv);
  if (authTagB64) {
    const tag = b64ToBuf(authTagB64);
    decipher.setAuthTag(tag);
  } else {
    // If client appended tag at end, split last 16 bytes
    if (ciphertext.length > 16) {
      const tag = ciphertext.slice(ciphertext.length - 16);
      ciphertext = ciphertext.slice(0, ciphertext.length - 16);
      decipher.setAuthTag(tag);
    } else {
      throw new Error('missing_auth_tag');
    }
  }

  const ptBuf = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return ptBuf.toString('utf8');
}

// Public key endpoint (derive from private)
app.get('/public-key', (req, res) => {
  try {
    const keyObj = crypto.createPrivateKey({ key: PRIVATE_KEY_PEM, format: 'pem' });
    const pub = keyObj.export({ type: 'spki', format: 'pem' });
    res.type('text/plain').send(pub);
  } catch (e) {
    console.error('public-key error', e);
    res.status(500).json({ error: 'internal' });
  }
});

// register push subscription
// body: { userId, subscription }
app.post('/push-subscriptions', (req, res) => {
  const { userId, subscription } = req.body;
  if (!userId || !subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'invalid' });
  }

  const db = readDb();
  db.push_subscriptions[userId] = {
    endpoint: subscription.endpoint,
    keys: subscription.keys || {},
    updated_at: new Date().toISOString()
  };
  writeDb(db);
  res.status(201).json({ ok: true });
});

// fetch message by id (recipient should call this after push)
app.get('/messages/:id', (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const msg = db.messages[id];
  if (!msg) return res.status(404).json({ error: 'not_found' });

  // NOTE: In production, require authentication/authorization to ensure only recipient can GET
  res.json({
    id,
    senderId: msg.senderId,
    recipientId: msg.recipientId,
    messageCiphertext: msg.messageCiphertext,
    serverTimestamp: msg.serverTimestamp
  });
});

/**
 * POST /messages
 * body:
 * {
 *  senderId, recipientId, messageCiphertext,
 *  wrappedAuthKey, authBlob, authIv, authTag?, clientTimestamp?
 * }
 */
app.post('/messages', async (req, res) => {
  const body = req.body || {};
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

    // 2) decrypt authBlob
    let authPlain;
    try {
      authPlain = decryptAesGcm(aesKeyBuf, authIv, authBlob, authTag);
    } catch (e) {
      console.warn('auth decrypt failed', e.message);
      return res.status(400).json({ error: 'auth_decrypt_failed' });
    }

    // 3) parse auth: could be JSON with token or raw token
    let jwtToken = null;
    try {
      const parsed = JSON.parse(authPlain);
      if (parsed && parsed.token) jwtToken = parsed.token;
      else jwtToken = authPlain;
    } catch (e) {
      jwtToken = authPlain;
    }

    // 4) validate JWT if configured
    let authVerified = false;
    let decoded = null;
    if (JWT_PUBLIC_KEY_PEM) {
      try {
        decoded = jwt.verify(jwtToken, JWT_PUBLIC_KEY_PEM.replace(/\\n/g, '\n'), { algorithms: ['RS256'] });
        authVerified = true;
      } catch (e) {
        console.warn('jwt verify failed (RS256)', e.message);
        return res.status(401).json({ error: 'invalid_token' });
      }
    } else if (JWT_SECRET) {
      try {
        decoded = jwt.verify(jwtToken, JWT_SECRET);
        authVerified = true;
      } catch (e) {
        console.warn('jwt verify failed (HS256)', e.message);
        return res.status(401).json({ error: 'invalid_token' });
      }
    } else {
      // No JWT verification configured — WARNING: insecure for production
      console.warn('No JWT verification configured. auth not verified.');
      authVerified = false;
    }

    // Optional: check token subject matches senderId
    if (authVerified && decoded && decoded.sub && decoded.sub !== senderId) {
      console.warn('token sub mismatch', decoded.sub, '!=', senderId);
      return res.status(401).json({ error: 'invalid_token_subject' });
    }

    // 5) persist message meta into DB file
    const db = readDb();
    const messageId = genId();
    const serverTimestamp = new Date().toISOString();

    db.messages[messageId] = {
      id: messageId,
      senderId,
      recipientId,
      messageCiphertext,
      aesIv: authIv,
      auth_verified: authVerified,
      serverTimestamp,
      status: 'queued',
      created_at: new Date().toISOString()
    };
    writeDb(db);

    // 6) find push subscription
    const pushSub = db.push_subscriptions[recipientId];
    if (!pushSub) {
      db.messages[messageId].status = 'no-subscription';
      writeDb(db);
      return res.status(202).json({ message_id: messageId, status: 'no-subscription' });
    }

    // 7) prepare minimal push payload (silent)
    const payload = JSON.stringify({ message_id: messageId, serverTimestamp });

    try {
      // web-push requires subscription object with endpoint and keys
      await webpush.sendNotification(pushSub, payload);
      db.messages[messageId].status = 'pushed';
      writeDb(db);
      return res.status(201).json({ message_id: messageId, status: 'pushed', serverTimestamp });
    } catch (pushErr) {
      console.error('web-push error', pushErr && pushErr.stack ? pushErr.stack : pushErr);
      db.messages[messageId].status = 'push-failed';
      writeDb(db);
      return res.status(201).json({ message_id: messageId, status: 'push-failed' });
    }

  } catch (err) {
    console.error('processing error', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'processing_failed' });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`relay server listening on ${PORT}, DB_FILE=${DB_FILE}`);
});
