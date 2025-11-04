// server.js
// Render用 Node.js ウェブプッシュ中継サーバ (ESM)
import express from 'express';
import webpush from 'web-push';
import bodyParser from 'body-parser';
import fs from 'fs';
import crypto from 'crypto';

const app = express();

// ボディサイズ拡大（大きな暗号化データに備える）
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

// -------------------------------
// 環境変数
// -------------------------------
const PORT = process.env.PORT || 10000;
const VAPID_PUBLIC = process.env.VAPID_PUBLIC;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE;
const SERVER_PRIVKEY_CONTENTS = process.env.SERVER_PRIVKEY_CONTENTS;
const DB_FILE = process.env.DB_FILE || './db.json';

if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
  console.warn('Warning: VAPID_PUBLIC or VAPID_PRIVATE not set.');
}
if (!SERVER_PRIVKEY_CONTENTS) {
  console.warn('Warning: SERVER_PRIVKEY_CONTENTS not set.');
}

// -------------------------------
// データベース（簡易ファイル）
// -------------------------------
let messages = [];
try {
  if (fs.existsSync(DB_FILE)) {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    messages = raw ? JSON.parse(raw) : [];
  } else {
    fs.writeFileSync(DB_FILE, JSON.stringify([]));
  }
} catch (e) {
  console.error('DBロード失敗', e);
  messages = [];
}

function saveMessages() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(messages, null, 2));
  } catch (e) {
    console.error('DB保存失敗:', e);
  }
}

// -------------------------------
// Web Push設定
// -------------------------------
try {
  webpush.setVapidDetails(
    'mailto:noanaonaao6366@gmail.com',
    VAPID_PUBLIC,
    VAPID_PRIVATE
  );
} catch (e) {
  console.warn('web-push setVapidDetails error (will show at send time):', e && e.message);
}

// -------------------------------
// 受信＆中継エンドポイント
// リクエスト JSON must contain:
// {
//   "encrypted_key": "<base64 RSA-OAEP(SHA256) encrypted AES key>",
//   "iv": "<base64 IV>",
//   "payload": "<base64 AES-256-CBC encrypted subscription JSON>",
//   "message": "<optional message text>"
// }
// -------------------------------
app.post('/push', async (req, res) => {
  try {
    const { encrypted_key, iv, payload, message } = req.body;
    if (!encrypted_key || !iv || !payload) {
      return res.status(400).json({ error: 'Invalid request (missing fields)' });
    }

    // 1) RSA秘密鍵でAES鍵を復号（OAEP with SHA-256）
    const privateKeyObj = crypto.createPrivateKey({
      key: SERVER_PRIVKEY_CONTENTS,
      format: 'pem'
    });

    let aesKey;
    try {
      aesKey = crypto.privateDecrypt(
        {
          key: privateKeyObj,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        Buffer.from(encrypted_key, 'base64')
      );
    } catch (e) {
      console.error('RSA復号失敗:', e && e.message);
      return res.status(400).json({ error: 'RSA decryption failed', detail: e && e.message });
    }

    // 2) AESで購読情報を復号（AES-256-CBC + PKCS#7）
    const ivBuf = Buffer.from(iv, 'base64');
    const encryptedBuf = Buffer.from(payload, 'base64');

    let decrypted;
    try {
      const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, ivBuf);
      decrypted = Buffer.concat([decipher.update(encryptedBuf), decipher.final()]);
    } catch (e) {
      console.error('AES復号失敗:', e && e.message);
      return res.status(400).json({ error: 'AES decryption failed', detail: e && e.message });
    }

    // PKCS#7 パディング除去
    const padLen = decrypted[decrypted.length - 1];
    if (padLen < 1 || padLen > 16) {
      console.warn('警告: 不正なパディング長', padLen);
    }
    const unpadded = decrypted.slice(0, decrypted.length - padLen);

    let subscription;
    try {
      subscription = JSON.parse(unpadded.toString('utf8'));
    } catch (e) {
      console.error('購読情報JSON解析失敗:', e && e.message);
      return res.status(400).json({ error: 'Invalid subscription JSON', detail: e && e.message });
    }

    // 3) タイムスタンプと署名（サーバ秘密鍵で署名）
    const time = new Date().toISOString();
    const signer = crypto.createSign('SHA256');
    signer.update((message || '') + time);
    let signature;
    try {
      signature = signer.sign(SERVER_PRIVKEY_CONTENTS, 'base64');
    } catch (e) {
      console.error('署名失敗:', e && e.message);
      signature = null;
    }

    // 4) 保存（簡易）
    const entry = { subscription, message, time, signature };
    messages.push(entry);
    saveMessages();

    // 5) Web Push送信
    try {
      await webpush.sendNotification(subscription, JSON.stringify({ message, time, signature }));
    } catch (e) {
      console.error('web-push送信失敗:', e);
      // 送信失敗でも保存はしておく。クライアントへ詳細返す。
      return res.status(502).json({ error: 'web-push send failed', detail: e && (e.stack || e.message) });
    }

    console.log('✅ Push送信成功:', subscription.endpoint);
    return res.json({ ok: true, time });
  } catch (e) {
    console.error('予期せぬエラー:', e && e.stack ? e.stack : e);
    return res.status(500).json({ error: e && e.message });
  }
});

// -------------------------------
// メッセージ一覧取得
// -------------------------------
app.get('/messages', (req, res) => {
  res.json(messages);
});

// -------------------------------
// ヘルスチェック
// -------------------------------
app.get('/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// -------------------------------
// 起動
// -------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Relay server listening on port ${PORT}`);
});
