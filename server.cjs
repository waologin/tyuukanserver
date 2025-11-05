// server.js
// =======================================================
// Relay server for encrypted push relay
// Using only environment variables for key materials
// =======================================================
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const webpush = require('web-push');
const cors = require('cors');   // ← ① 追加

// ---------- 環境変数設定 ----------
const SERVER_RSA_PRIV_PEM = process.env.SERVER_RSA_PRIV_PEM;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@example.com';
const PORT = process.env.PORT || 3000;

// ---------- 初期化 ----------
webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
const app = express();
app.use(cors());                // ← ② 追加（全オリジン許可）
app.use(bodyParser.json({ limit: '512kb' }));

// ---------- 検証 ----------
if (!SERVER_RSA_PRIV_PEM) {
  console.error('ERROR: SERVER_RSA_PRIV_PEM is not set.');
  process.exit(1);
}
if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error('WARNING: VAPID keys not set. Push may fail.');
}

// ---------- ユーティリティ ----------
const b64ToBuf = (b64) => Buffer.from(b64, 'base64');
const nowIso = () => new Date().toISOString();

// AES-GCM復号
function decryptAesGcm(encB64, ivB64, rawKeyBuf) {
  const data = b64ToBuf(encB64);
  const tag = data.slice(data.length - 16);
  const ciphertext = data.slice(0, data.length - 16);
  const iv = b64ToBuf(ivB64);

  const decipher = crypto.createDecipheriv('aes-256-gcm', rawKeyBuf, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString('utf8');
}

// RSA-OAEP復号 (AES鍵を復号)
function unwrapWithRsaOaep(wrappedKeyB64) {
  const wrappedBuf = b64ToBuf(wrappedKeyB64);
  return crypto.privateDecrypt(
    {
      key: SERVER_RSA_PRIV_PEM,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    wrappedBuf
  );
}

// Web Push送信
async function sendPush(subscription, payloadObj, ttl = 60) {
  const payload = JSON.stringify(payloadObj);
  const options = { TTL: ttl };
  return webpush.sendNotification(subscription, payload, options);
}

// ---------- API ----------
app.post('/sendPush', async (req, res) => {
  try {
    const {
      senderId,
      recipientId,
      message,
      encAuth,
      iv,
      wrappedKey,
      clientTimestamp
    } = req.body;

    if (!senderId || !recipientId || !message || !encAuth || !iv || !wrappedKey) {
      return res.status(400).json({ error: 'missing fields' });
    }

    // 1) RSA-OAEPでAES鍵を復号
    let aesKey;
    try {
      aesKey = unwrapWithRsaOaep(wrappedKey);
    } catch (e) {
      console.error('unwrap failed:', e.message);
      return res.status(401).json({ error: 'invalid wrappedKey' });
    }

    // 2) AES-GCMでauth情報を復号
    let authBlob;
    try {
      const authJson = decryptAesGcm(encAuth, iv, aesKey);
      authBlob = JSON.parse(authJson);
    } catch (e) {
      console.error('auth decrypt failed:', e.message);
      return res.status(400).json({ error: 'auth decrypt failed' });
    }

    if (
      !authBlob.endpoint ||
      !authBlob.keys ||
      !authBlob.keys.p256dh ||
      !authBlob.keys.auth
    ) {
      return res.status(400).json({ error: 'invalid auth blob' });
    }

    // 3) サーバタイムスタンプ付与
    const serverTimestamp = nowIso();

    // 4) Push送信用オブジェクト作成
    const payload = {
      senderId,
      recipientId,
      message,
      serverTimestamp,
      clientTimestamp
    };

    const subscription = {
      endpoint: authBlob.endpoint,
      keys: {
        p256dh: authBlob.keys.p256dh,
        auth: authBlob.keys.auth
      }
    };

    const ttl = authBlob.ttl || 60;

    // 5) Push送信
    try {
      await sendPush(subscription, payload, ttl);
      console.log(`[PUSH OK] ${recipientId} at ${serverTimestamp}`);
      return res.status(200).json({ status: 'ok', serverTimestamp });
    } catch (err) {
      console.error('push failed:', err.statusCode || err.message);
      const status = err.statusCode || 502;
      return res.status(status).json({ error: 'push send failed' });
    }
  } catch (err) {
    console.error('internal error:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// ---------- 公開鍵取得ユーティリティ ----------
function getServerPublicKeyPem() {
  try {
    const pubKeyObj = crypto.createPublicKey(SERVER_RSA_PRIV_PEM);
    const pubPem = pubKeyObj.export({ type: 'spki', format: 'pem' });
    return pubPem;
  } catch (err) {
    console.error('failed to derive public key:', err.message);
    return null;
  }
}

// ---------- 公開鍵取得エンドポイント ----------
app.get('/publicKey', (req, res) => {
  const pubPem = getServerPublicKeyPem();
  if (!pubPem) {
    return res.status(500).json({ error: 'failed to derive public key' });
  }
  res.json({ publicKeyPem: pubPem });
});

// ---------- VAPID 公開鍵取得 ----------
app.get('/vapidPublicKey', (req, res) => {
  if (!VAPID_PUBLIC_KEY) return res.status(404).json({ error: 'vapid key not configured' });
  res.json({ vapidPublicKey: VAPID_PUBLIC_KEY });
});

// healthチェック
app.get('/_health', (req, res) => res.json({ status: 'ok', time: nowIso() }));

app.listen(PORT, () => {
  console.log(`Relay server running on port ${PORT}`);
});
