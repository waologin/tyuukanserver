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
// データベースの代わり
// -------------------------------
let messages = [];
if (fs.existsSync(DB_FILE)) {
  try {
    const content = fs.readFileSync(DB_FILE, 'utf8');
    messages = JSON.parse(content);
  } catch {
    messages = [];
  }
}

function saveMessages() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(messages, null, 2));
  } catch (e) {
    console.error('Failed to save DB:', e);
  }
}

// -------------------------------
// Web Push 設定
// -------------------------------
webpush.setVapidDetails(
  'mailto:noanaonaao6366@gmail.com',
  VAPID_PUBLIC,
  VAPID_PRIVATE
);

// -------------------------------
// メッセージ保存 & 転送
// -------------------------------
app.post('/push', async (req, res) => {
  try {
    const { to, payload } = req.body;
    if (!to || !payload) return res.status(400).json({ error: 'Invalid request' });

    // タイムスタンプを付与
    const time = new Date().toISOString();

    // サーバ秘密鍵でサイン
    const signer = crypto.createSign('SHA256');
    signer.update(payload + time);
    const signature = signer.sign(SERVER_PRIVKEY_CONTENTS, 'base64');

    // データ保存
    const entry = { to, payload, time, signature };
    messages.push(entry);
    saveMessages();

    // Web Push送信
    await webpush.sendNotification(to, JSON.stringify({ payload, time, signature }));

    res.json({ ok: true, time });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -------------------------------
// メッセージ取得
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
  console.log(`Relay server listening on port ${PORT}`);
});
