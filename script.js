require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const FICHIER_POSTS = path.join(__dirname, 'posts.json');

// ===== Middleware =====
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 4 // 4h
  }
}));

// ===== Stockage posts (fichier JSON) =====
function lirePosts(){
  if(!fs.existsSync(FICHIER_POSTS)) return [];
  try { return JSON.parse(fs.readFileSync(FICHIER_POSTS, 'utf8')); }
  catch { return []; }
}
function ecrirePosts(posts){
  fs.writeFileSync(FICHIER_POSTS, JSON.stringify(posts, null, 2));
}

// ===== Auth middleware =====
function requireAdmin(req, res, next){
  if(req.session && req.session.admin === true) return next();
  res.status(401).json({ erreur: 'Non autorisé' });
}

// ===== Rate limiting simple sur le login =====
const tentatives = new Map();
function tropDeTentatives(ip){
  const now = Date.now();
  const data = tentatives.get(ip) || { count: 0, first: now };
  if(now - data.first > 15 * 60 * 1000){
    tentatives.set(ip, { count: 1, first: now });
    return false;
  }
  data.count++;
  tentatives.set(ip, data);
  return data.count > 8;
}

/* ================= ROUTES PUBLIQUES ================= */

// Liste des posts (lecture seule pour tous)
app.get('/api/posts', (req, res) => {
  res.json(lirePosts());
});

/* ================= ROUTES AUTH ================= */

app.post('/api/login', async (req, res) => {
  const ip = req.ip;
  if(tropDeTentatives(ip)){
    return res.status(429).json({ erreur: 'Trop de tentatives. Réessaie plus tard.' });
  }

  const { motdepasse } = req.body || {};
  if(typeof motdepasse !== 'string' || !motdepasse){
    return res.status(400).json({ erreur: 'Mot de passe requis' });
  }

  const hash = process.env.ADMIN_PASSWORD_HASH;
  if(!hash) return res.status(500).json({ erreur: 'Serveur mal configuré' });

  const ok = await bcrypt.compare(motdepasse, hash);
  if(!ok){
    // délai anti-bruteforce
    await new Promise(r => setTimeout(r, 800));
    return res.status(401).json({ erreur: 'Mot de passe incorrect' });
  }

  req.session.admin = true;
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/moi', (req, res) => {
  res.json({ admin: !!(req.session && req.session.admin) });
});

/* ================= ROUTES ADMIN ================= */

app.post('/api/posts', requireAdmin, (req, res) => {
  const { texte } = req.body || {};
  if(typeof texte !== 'string' || !texte.trim()){
    return res.status(400).json({ erreur: 'Texte vide' });
  }
  const posts = lirePosts();
  const nouveau = {
    id: crypto.randomUUID(),
    texte: texte.trim(),
    date: new Date().toISOString()
  };
  posts.unshift(nouveau);
  ecrirePosts(posts);
  res.json(nouveau);
});

app.put('/api/posts/:id', requireAdmin, (req, res) => {
  const { texte } = req.body || {};
  if(typeof texte !== 'string' || !texte.trim()){
    return res.status(400).json({ erreur: 'Texte vide' });
  }
  const posts = lirePosts();
  const idx = posts.findIndex(p => p.id === req.params.id);
  if(idx === -1) return res.status(404).json({ erreur: 'Post introuvable' });
  posts[idx].texte = texte.trim();
  posts[idx].modifie = new Date().toISOString();
  ecrirePosts(posts);
  res.json(posts[idx]);
});

app.delete('/api/posts/:id', requireAdmin, (req, res) => {
  const posts = lirePosts();
  const filtres = posts.filter(p => p.id !== req.params.id);
  if(filtres.length === posts.length){
    return res.status(404).json({ erreur: 'Post introuvable' });
  }
  ecrirePosts(filtres);
  res.json({ ok: true });
});

// ===== Démarrage =====
app.listen(PORT, () => {
  console.log(`⚖️  Serveur Lelouch lancé sur http://localhost:${PORT}`);
});