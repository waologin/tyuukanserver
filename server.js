// Render用 Node.js ウェブプッシュ中継サーバ

import express from 'express';
import webpush from 'web-push';
import bodyParser from 'body-parser';
import fs from 'fs';
import crypto from 'crypto';

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));

// -------------------------------
// 環境変数
// -------------------------------
const PORT = process.env.PORT || 10000;
const VAPID_PUBLIC = process.env.VAPID_PUBLIC;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE;
const SERVER_PRIVKEY_CONTENTS = process.env.SERVER_PRIVKEY_CONTENTS;
const DB_FILE = process.env.DB_FILE || './db.json';

// -------------------------------
// データベース（簡易）
// -------------------------------
let messages = [];
if (fs.existsSync(DB_FILE)) {
  try {
    messages = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    messages = [];
  }
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
webpush.setVapidDetails(
  'mailto:noanaonaao6366@gmail.com',
  VAPID_PUBLIC,
  VAPID_PRIVATE
);

// -------------------------------
// 受信＆中継
// -------------------------------
app.post('/push', async (req, res) => {
  try {
    const { to, iv, payload, message } = req.body;
    if (!to || !iv || !payload) {
      return res.status(400).json({ error: 'Invalid request (missing fields)' });
    }

    // 1️⃣ RSA秘密鍵でAES鍵を復号
    const privateKey = crypto.createPrivateKey({
      key: SERVER_PRIVKEY_CONTENTS,
      format: 'pem'
    });
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(to, 'base64')
    );

    // 2️⃣ AESで購読情報を復号
    const ivBuf = Buffer.from(iv, 'base64');
    const encrypted = Buffer.from(payload, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, ivBuf);
    let decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    // PKCS#7パディング除去
    const padLen = decrypted[decrypted.length - 1];
    decrypted = decrypted.slice(0, -padLen);

    const subscription = JSON.parse(decrypted.toString('utf-8'));

    // 3️⃣ タイムスタンプと署名
    const time = new Date().toISOString();
    const signer = crypto.createSign('SHA256');
    signer.update((message || '') + time);
    const signature = signer.sign(SERVER_PRIVKEY_CONTENTS, 'base64');

    // 4️⃣ メッセージ保存
    const entry = { subscription, message, time, signature };
    messages.push(entry);
    saveMessages();

    // 5️⃣ Web Push送信
    await webpush.sendNotification(subscription, JSON.stringify({ message, time, signature }));

    res.json({ ok: true, time });
    console.log('✅ Push送信成功:', subscription.endpoint);
  } catch (e) {
    console.error('❌ Push送信失敗:', e);
    res.status(500).json({ error: e.message });
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
