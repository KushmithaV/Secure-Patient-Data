// server.js
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

// Change this secret only for your local demo. In production use a secure vault.
const SERVER_HMAC_SECRET = process.env.HMAC_SECRET || 'change_this_server_secret';

// Where encrypted records will be appended (JSONL)
const STORE_FILE = path.join(__dirname, 'encrypted_records.jsonl');

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json({limit: '200kb'}));

// Endpoint to receive encrypted patient data
// Expects JSON: { patientId, payload: { salt, iv, ciphertext }, meta: { name, timestamp } }
app.post('/submit', (req, res) => {
  try {
    const body = req.body;
    if (!body || !body.payload || !body.meta) {
      return res.status(400).json({ error: 'invalid payload' });
    }

    // We compute HMAC over the ciphertext + salt + iv to ensure integrity on server side
    const h = crypto.createHmac('sha256', SERVER_HMAC_SECRET);
    const toHmac = (body.payload.salt || '') + '|' + (body.payload.iv || '') + '|' + (body.payload.ciphertext || '');
    h.update(toHmac);
    const hmac = h.digest('base64');

    const record = {
      storedAt: new Date().toISOString(),
      meta: body.meta,
      payload: body.payload,
      hmac
    };

    // Append one JSON object per line (simple local store)
    fs.appendFileSync(STORE_FILE, JSON.stringify(record) + '\n', { encoding: 'utf8' });

    res.json({ ok: true, storedAt: record.storedAt });
  } catch (err) {
    console.error('Error storing record', err);
    res.status(500).json({ error: 'internal error' });
  }
});

// Simple endpoint to list stored (encrypted) records for demo purposes
// WARNING: This returns encrypted blobs only. Do not expose in production.
app.get('/records', (req, res) => {
  try {
    if (!fs.existsSync(STORE_FILE)) {
      return res.json([]);
    }
    const lines = fs.readFileSync(STORE_FILE, 'utf8').trim().split('\n').filter(Boolean);
    const arr = lines.map(l => JSON.parse(l));
    res.json(arr);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'internal' });
  }
});

app.get("/getRecord", (req, res) => {
  const id = req.query.id;
  if (!id) return res.json({ error: "Missing ID" });

  try {
    const lines = fs.readFileSync("encrypted_records.jsonl", "utf8").trim().split("\n");
    for (const line of lines) {
      const record = JSON.parse(line);
      if (record.meta && record.meta.patientId === id) {
        return res.json(record);
      }
    }
    res.json({ error: "Not found" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
