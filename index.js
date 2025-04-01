const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const http = require('http');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const loki = require('lokijs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
// Konfigurasi Socket.io tetap sama
const io = new Server(server, { cors: { origin: "*" } });
const saltRounds = 10;

// Secret key untuk JWT (sebaiknya simpan di environment variable)
const JWT_SECRET = 'rahasia_super_kuat';

// Buat folder "data" jika belum ada
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Folder rules dan load file rules.json
const rulesPath = path.join(__dirname, 'rules', 'rules.json');
let rules = {};
if (fs.existsSync(rulesPath)) {
  try {
    rules = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
  } catch (e) {
    console.error("Gagal memuat rules:", e);
  }
}



app.use(cors({
  origin: ['http://localhost:8080', 'https://databasegithubio-production.up.railway.app', 'https://anotherdomain.com'],
  credentials: true
}));


app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cookieParser());

/**
 * Fungsi untuk mendapatkan (atau membuat jika belum ada) database LokiJS
 * untuk koleksi tertentu. Data disimpan dalam file JSON di folder "data"
 * dengan nama file sesuai dengan nama koleksi (misalnya: "products.json").
 */
function getCollectionDB(collectionName) {
  const filePath = path.join(dataDir, `${collectionName}.json`);
  let db = new loki(filePath);
  // Jika file sudah ada, load data dari file
  if (fs.existsSync(filePath)) {
    const data = fs.readFileSync(filePath, 'utf-8');
    try {
      db.loadJSON(data);
    } catch (err) {
      console.error(`Gagal memuat file ${filePath}:`, err);
    }
  }
  let coll = db.getCollection(collectionName);
  if (!coll) {
    coll = db.addCollection(collectionName, { unique: ['id'] });
  }
  return { db, coll, filePath };
}

/**
 * Fungsi untuk menyimpan database ke file.
 */
function saveCollectionDB(db, filePath) {
  const data = db.serialize();
  fs.writeFileSync(filePath, data, 'utf-8');
}

/**
 * Fungsi untuk mengevaluasi rule.
 */
function evaluateRule(rule, auth, data = {}) {
  try {
    return Function("auth", "data", "return (" + rule + ")")(auth, data);
  } catch (e) {
    console.error("Error evaluating rule. Terjadi kesalahan saat evaluasi aturan.", e);
    return false;
  }
}

/**
 * Fungsi untuk mendapatkan user yang login dari token (di header atau cookie).
 * Token diverifikasi dengan JWT_SECRET. Jika valid, payload dari token (misalnya uid) dikembalikan.
 */
function getAuth(req) {
  let token = req.headers.authorization;
  if (token && token.startsWith('Bearer ')) {
    token = token.slice(7);
  } else if (req.cookies.token) {
    token = req.cookies.token;
  } else {
    return null;
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Ambil user dari database berdasarkan uid yang ada di payload token
    const { coll } = getCollectionDB('users');
    const user = coll.findOne({ uid: decoded.uid });
    return user;
  } catch (e) {
    console.error("Token tidak valid:", e.message);
    return null;
  }
}

/**
 * Middleware untuk mengecek rules berdasarkan koleksi dan aksi.
 */
function checkRules(collection, action, req, res, next, dataForRule = {}) {
  const auth = getAuth(req);
  const rule = (rules[collection] && rules[collection][action]) || "true";
  if (!evaluateRule(rule, auth, dataForRule)) {
    console.error(`[RULES] Akses ${action} ditolak untuk koleksi ${collection}. User: ${auth ? auth.email : 'tidak ada user'}`);
    return res.status(403).json({ error: `Akses ${action} tidak diizinkan untuk koleksi ${collection}` });
  }
  next();
}

/**
 * Endpoint /db untuk operasi CRUD
 */
// GET: Mengambil koleksi atau query dokumen
app.get('/db', (req, res, next) => {
  const { collection, field, operator, value, skip, limit } = req.query;
  if (!collection) {
    console.error("[GET] Gagal: Parameter collection tidak ada");
    return res.status(400).json({ error: 'Parameter collection wajib ada' });
  }
  checkRules(collection, "read", req, res, () => {
    const { db, coll } = getCollectionDB(collection);
    let docs = coll.find();
    if (field && operator && value !== undefined) {
      if (operator === '==') {
        docs = docs.filter(doc => doc[field] == value);
      }
    }
    const skipNum = parseInt(skip) || 0;
    const limitNum = parseInt(limit);
    if (!isNaN(limitNum)) {
      docs = docs.slice(skipNum, skipNum + limitNum);
    } else if (skipNum > 0) {
      docs = docs.slice(skipNum);
    }
    console.log(`[GET] Koleksi '${collection}' berhasil dimuat, jumlah dokumen: ${docs.length}`);
    res.json(docs);
  });
});

// POST: Menambahkan dokumen ke koleksi
app.post('/db', (req, res, next) => {
  const { collection } = req.query;
  if (!collection) {
    console.error("[POST] Gagal: Parameter collection tidak ada");
    return res.status(400).json({ error: 'Parameter collection wajib ada' });
  }
  checkRules(collection, "write", req, res, () => {
    const newDoc = req.body;
    if (!newDoc.id) {
      console.error("[POST] Gagal: Dokumen harus memiliki property 'id'");
      return res.status(400).json({ error: "Property 'id' wajib ada pada dokumen" });
    }
    const { db, coll, filePath } = getCollectionDB(collection);
    try {
      coll.insert(newDoc);
      saveCollectionDB(db, filePath);
    } catch (err) {
      console.error("[POST] Error menambahkan dokumen:", err.message);
      return res.status(500).json({ error: 'Gagal menambahkan dokumen' });
    }
    console.log(`[POST] Dokumen baru ditambahkan ke koleksi '${collection}'`);
    io.emit('update', { collection, doc: newDoc });
    res.json(newDoc);
  });
});

// PUT: Memperbarui dokumen berdasarkan id
app.put('/db', (req, res, next) => {
  const { collection, id } = req.query;
  if (!collection || !id) {
    console.error("[PUT] Gagal: Parameter collection atau id tidak ada");
    return res.status(400).json({ error: 'Parameter collection dan id wajib ada' });
  }
  checkRules(collection, "update", req, res, () => {
    const { db, coll, filePath } = getCollectionDB(collection);
    let existingDoc = coll.findOne({ id: id });
    if (!existingDoc) {
      console.error(`[PUT] Gagal: Dokumen dengan ID ${id} tidak ditemukan di koleksi '${collection}'`);
      return res.status(404).json({ error: 'Dokumen tidak ditemukan' });
    }
    console.log(`[PUT] Sebelum update, dokumen ditemukan`);
    const updatedDoc = { ...existingDoc, ...req.body, id };
    coll.update(updatedDoc);
    saveCollectionDB(db, filePath);
    console.log(`[PUT] Setelah update, dokumen diperbarui`);
    io.emit('update', { collection, doc: updatedDoc });
    res.json(updatedDoc);
  }, { id: id });
});

// DELETE: Menghapus dokumen berdasarkan id
app.delete('/db', (req, res, next) => {
  const { collection, id } = req.query;
  if (!collection || !id) {
    console.error("[DELETE] Gagal: Parameter collection atau id tidak ada");
    return res.status(400).json({ error: 'Parameter collection dan id wajib ada' });
  }
  checkRules(collection, "delete", req, res, () => {
    const { db, coll, filePath } = getCollectionDB(collection);
    let doc = coll.findOne({ id: id });
    if (!doc) {
      console.error(`[DELETE] Dokumen dengan ID ${id} tidak ditemukan di koleksi '${collection}'`);
      return res.status(404).json({ error: 'Dokumen tidak ditemukan' });
    }
    coll.remove(doc);
    saveCollectionDB(db, filePath);
    console.log(`[DELETE] Dokumen dengan ID ${id} berhasil dihapus dari koleksi '${collection}'`);
    io.emit('update', { collection });
    res.json({ success: true, message: `Dokumen ID ${id} telah dihapus` });
  });
});

/**
 * Endpoint Admin: Daftar koleksi (file JSON di folder data)
 */
app.get('/admin/collections', (req, res) => {
  fs.readdir(dataDir, (err, files) => {
    if (err) {
      console.error("Error membaca direktori data:", err);
      return res.status(500).json({ error: 'Gagal membaca direktori data' });
    }
    const collections = files.filter(file => file.endsWith('.json')).map(file => path.basename(file, '.json'));
    res.json({ collections });
  });
});

/**
 * Endpoint Admin: Register dan Login
 * Format user: username, email, pin (4 digit), password (terenkripsi), uid, status ("member")
 */

// Register user baru (admin/register)
app.post('/admin/register', async (req, res) => {
  const { username, email, pin, password } = req.body;
  if (!username || !email || !pin || !password) {
    console.error("[REGISTER] Gagal: Parameter tidak lengkap");
    return res.status(400).json({ error: 'Username, email, pin, dan password wajib ada' });
  }
  const { coll: userColl } = getCollectionDB('users');
  if (userColl.findOne({ username: username })) {
    console.error(`[REGISTER] Gagal: Username ${username} sudah digunakan`);
    return res.status(400).json({ error: 'Username sudah digunakan, gunakan username lain' });
  }
  if (!/^\d{4}$/.test(pin)) {
    console.error("[REGISTER] Gagal: PIN tidak valid");
    return res.status(400).json({ error: 'PIN harus 4 digit' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const status = 'member';
    // Generate uid secara acak (sebagai identitas user)
    const uid = crypto.randomBytes(8).toString('hex');
    const userDoc = { id: email, uid, username, email, pin, password: hashedPassword, status };
    const { db, coll, filePath } = getCollectionDB('users');
    try {
      coll.insert(userDoc);
      saveCollectionDB(db, filePath);
      // Buat JWT token untuk user
      const token = jwt.sign({ uid: uid, email: email }, JWT_SECRET, { expiresIn: '1h' });
      // Kirim token melalui cookie (httpOnly) dan respons JSON
      res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'lax' });
      res.cookie('user', JSON.stringify({ uid, username, email }), { httpOnly: false });
      console.log(`[REGISTER] User ${email} berhasil didaftarkan dengan uid ${uid}`);
      res.json({ success: true, message: 'User terdaftar', user: { uid, username, email, pin, status } });
    } catch (err) {
      console.error("[REGISTER] Error saat menyimpan user:", err.message);
      return res.status(500).json({ error: 'Gagal mendaftarkan user. Mungkin user sudah terdaftar.' });
    }
  } catch (err) {
    console.error("[REGISTER] Error saat mengenkripsi password:", err.message);
    return res.status(500).json({ error: 'Gagal mengenkripsi password' });
  }
});

// Login user (admin/login) dengan validasi 3 kali password salah dan pembuatan JWT token
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    console.error("[LOGIN] Gagal: Email atau password tidak lengkap");
    return res.status(400).json({ error: 'Email dan password diperlukan' });
  }
  const { db, coll, filePath } = getCollectionDB('users');
  const user = coll.findOne({ email: email });
  if (!user) {
    console.error(`[LOGIN] Gagal: User dengan email ${email} tidak ditemukan`);
    return res.status(404).json({ error: 'User tidak ditemukan' });
  }
  // Jika akun sudah dinonaktifkan, tolak login
  if (user.disabled) {
    console.error(`[LOGIN] Gagal: Akun dengan email ${email} telah diblokir`);
    return res.status(403).json({ error: 'Akun diblokir' });
  }
  try {
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      // Reset counter kesalahan login jika berhasil
      user.failedLoginAttempts = 0;
      saveCollectionDB(db, filePath);
      // Buat JWT token
      const token = jwt.sign({ uid: user.uid, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
      // Set cookie dengan token dan juga simpan data user di cookie (non-sensitive)
      res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'lax' });
      res.cookie('user', JSON.stringify({ uid: user.uid, username: user.username, email: user.email }), { httpOnly: false });
      console.log(`[LOGIN] User ${email} berhasil login dengan uid ${user.uid}`);
      // Kirim respons lengkap ke frontend
      res.json({ success: true, message: 'Login berhasil', user: { uid: user.uid, username: user.username, email: user.email } });
    } else {
      // Jika password salah, tingkatkan counter dan cek apakah sudah mencapai 3 kali
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= 3) {
        user.disabled = true;
        saveCollectionDB(db, filePath);
        console.error(`[LOGIN] Gagal: Akun dengan email ${email} diblokir karena kesalahan login berulang`);
        return res.status(403).json({ error: 'Akun diblokir karena kesalahan login berulang' });
      }
      saveCollectionDB(db, filePath);
      console.error(`[LOGIN] Gagal: Password salah untuk email ${email}`);
      res.status(401).json({ error: 'Password salah' });
    }
  } catch (err) {
    console.error("[LOGIN] Error saat verifikasi password:", err.message);
    res.status(500).json({ error: 'Gagal memverifikasi password' });
  }
});

// Endpoint untuk mendeteksi apakah pengguna sudah login atau tidak
app.get('/admin/check', (req, res) => {
  const user = getAuth(req);
  if (user) {
    res.json({ loggedIn: true, user: { uid: user.uid, username: user.username, email: user.email, status: user.status } });
  } else {
    console.error("[CHECK] Gagal: token tidak valid atau tidak ditemukan");
    res.status(401).json({ loggedIn: false, error: 'Token tidak valid atau tidak ditemukan' });
  }
});

// Endpoint untuk logout
app.post('/admin/logout', (req, res) => {
  // Hapus cookie token dan user
  res.clearCookie('token');
  res.clearCookie('user');
  res.json({ success: true, message: "Logout berhasil" });
});


const PORT = process.env.PORT || 3030;
server.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));


