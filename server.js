// server.js
// Node 14+ 想定
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const webpush = require('web-push');

const app = express();
app.use(bodyParser.json({ limit: '512kb' }));

/*
  環境変数 / 設定（実運用では KMS/HSM などを使うこと）
  - SERVER_RSA_PRIV_PATH or SERVER_RSA_PRIV_PEM: サーバ秘密鍵のパスまたは PEM 文字列
  - VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT: web-push のため
*/
const SERVER_RSA_PRIV_PEM = process.env.SERVER_RSA_PRIV_PEM || null;
const SERVER_RSA_PRIV_PATH = process.env.SERVER_RSA_PRIV_PATH || null;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || null;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || null;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';

// load private key
let serverPrivateKeyPem = SERVER_RSA_PRIV_PEM;
if (!serverPrivateKeyPem && SERVER_RSA_PRIV_PATH) {
  const fs = require('fs');
  serverPrivateKeyPem = fs.readFileSync(SERVER_RSA_PRIV_PATH, 'utf8');
}
if (!serverPrivateKeyPem) {
  console.warn('WARNING: SERVER RSA PRIVATE KEY not provided. Set SERVER_RSA_PRIV_PEM or SERVER_RSA_PRIV_PATH.');
}

// setup VAPID if provided
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} else {
  console.warn('WARNING: VAPID keys not set. web-push may fail if VAPID is required by push service.');
}

/* ======= ユーティリティ ======= */
function b64ToBuffer(b64) {
  return Buffer.from(b64, 'base64');
}

function nowIso() {
  return new Date().toISOString();
}

/* 検証用プレースホルダ:
   本番では DB の subscription 登録情報と senderId の紐付けを確認する等の実装が必要
*/
async function verifyAuthOwnership(authBlob, senderId) {
  // authBlob から endpoint 取得して DB で確認する想定
  // ここでは単純に true を返す（実装すること）
  return true;
}

/* AES-GCM 復号（encAuth: base64(ciphertext||tag), iv: base64, key: Buffer (raw 32 bytes) ) */
function decryptAesGcm(encAuth_b64, iv_b64, rawKeyBuf) {
  const ctAndTag = b64ToBuffer(encAuth_b64);
  if (ctAndTag.length < 16) throw new Error('ciphertext too short');
  const tag = ctAndTag.slice(ctAndTag.length - 16);
  const ciphertext = ctAndTag.slice(0, ctAndTag.length - 16);
  const iv = b64ToBuffer(iv_b64);

  const decipher = crypto.createDecipheriv('aes-256-gcm', rawKeyBuf, iv);
  decipher.setAuthTag(tag);
  const plainBuf = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plainBuf.toString('utf8');
}

/* RSA-OAEP unwrap wrappedKey (base64) -> returns Buffer raw key */
function unwrapWithRsaOaep(wrappedKey_b64) {
  if (!serverPrivateKeyPem) throw new Error('Server private key not configured');
  const wrappedBuf = b64ToBuffer(wrappedKey_b64);
  const raw = crypto.privateDecrypt(
    {
      key: serverPrivateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    wrappedBuf
  );
  return raw; // Buffer (raw AES key bytes)
}

/* Push 送信
   subscription: object with endpoint and keys (p256dh, auth)
   payloadObj: object -> will be JSON-stringified as payload
   ttl: optional
*/
async function sendWebPush(subscription, payloadObj, ttl = 60) {
  const payloadStr = JSON.stringify(payloadObj);
  const options = { TTL: ttl };
  // VAPID が設定されているなら web-push が自動的に使う
  return webpush.sendNotification(subscription, payloadStr, options);
}

/* ======= API ======= */

/*
  POST /sendPush
  Body JSON:
  {
    senderId,
    recipientId,
    message,
    encAuth,       // base64 (ciphertext||tag)
    iv,            // base64 (12 bytes)
    wrappedKey,    // base64
    clientTimestamp,
    signature(optional)
  }
*/
app.post('/sendPush', async (req, res) => {
  try {
    const {
      senderId,
      recipientId,
      message,
      encAuth,
      iv,
      wrappedKey,
      clientTimestamp,
      signature
    } = req.body;

    if (!senderId || !recipientId || !message || !encAuth || !iv || !wrappedKey) {
      return res.status(400).json({ error: 'missing required fields' });
    }

    // 1) unwrap wrappedKey with server private key
    let rawAesKey;
    try {
      rawAesKey = unwrapWithRsaOaep(wrappedKey); // Buffer
    } catch (err) {
      console.error('wrappedKey unwrap failed:', err.message);
      return res.status(401).json({ error: 'invalid wrappedKey' });
    }

    // Expect AES-256 => 32 bytes
    if (rawAesKey.length !== 32) {
      console.warn('Warning: AES key length != 32 (got %d)', rawAesKey.length);
      // proceed cautiously or reject
      // return res.status(400).json({ error: 'invalid AES key length' });
    }

    // 2) decrypt encAuth with AES-GCM
    let authJsonStr;
    try {
      authJsonStr = decryptAesGcm(encAuth, iv, rawAesKey);
    } catch (err) {
      console.error('encAuth decrypt failed:', err.message);
      return res.status(400).json({ error: 'failed to decrypt auth blob' });
    }

    let authBlob;
    try {
      authBlob = JSON.parse(authJsonStr);
    } catch (err) {
      console.error('authBlob parse failed:', err.message);
      return res.status(400).json({ error: 'invalid auth blob JSON' });
    }

    // 3) basic validity checks
    // example authBlob structure: { endpoint, keys: { p256dh, auth }, expiresAt, ttl }
    if (!authBlob.endpoint || !authBlob.keys || !authBlob.keys.p256dh || !authBlob.keys.auth) {
      console.error('authBlob missing required fields');
      return res.status(400).json({ error: 'invalid auth blob content' });
    }

    // 4) ownership / authorization check (placeholder)
    const okOwner = await verifyAuthOwnership(authBlob, senderId);
    if (!okOwner) {
      console.warn('auth ownership verification failed for sender:', senderId);
      return res.status(403).json({ error: 'auth not owned by sender' });
    }

    // 5) expiresAt check if present
    if (authBlob.expiresAt) {
      const expires = new Date(authBlob.expiresAt).getTime();
      if (isNaN(expires) || Date.now() > expires) {
        console.warn('auth blob expired');
        return res.status(410).json({ error: 'auth blob expired' });
      }
    }

    // 6) prepare push payload and serverTimestamp
    const serverTimestamp = nowIso();
    const pushPayload = {
      senderId,
      recipientId,
      message,
      serverTimestamp,
      // optional: include clientTimestamp if needed: clientTimestamp
    };

    // 7) prepare subscription object for web-push
    const subscription = {
      endpoint: authBlob.endpoint,
      keys: {
        p256dh: authBlob.keys.p256dh,
        auth: authBlob.keys.auth
      }
    };

    // TTL fallback
    const ttl = authBlob.ttl || 60;

    // 8) send push (web-push)
    try {
      const pushResult = await sendWebPush(subscription, pushPayload, ttl);
      // pushResult is a Response-like object from web-push; logging minimal info
      console.log('Push sent success:', pushResult && pushResult.statusCode ? pushResult.statusCode : 'ok');

      // 9) persist log/metadata (placeholder)
      // TODO: save (senderId, recipientId, serverTimestamp, status, endpoint hash, etc.) to DB
      // Do NOT save sensitive decrypted auth keys or raw AES keys.

      return res.status(200).json({ status: 'ok', serverTimestamp });
    } catch (err) {
      console.error('Push send failed:', err);
      // if push service returns 410/404, subscription should be removed from DB
      const statusCode = err && err.statusCode ? err.statusCode : null;
      if (statusCode === 410 || statusCode === 404) {
        // TODO: mark subscription as invalid / remove
        console.warn('Push subscription gone; should remove from DB.');
      }
      return res.status(502).json({ error: 'push send failed', detail: err && err.message });
    }
  } catch (err) {
    console.error('internal error:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

/* health */
app.get('/_health', (req, res) => res.json({ status: 'ok', ts: nowIso() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`relay server listening on ${PORT}`);
});
