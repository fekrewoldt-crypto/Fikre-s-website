require('dotenv').config();

// Verify NODE_ENV is set appropriately
const allowedEnv = ['development', 'test', 'production'];
if (!allowedEnv.includes(process.env.NODE_ENV)) {
  console.error('CRITICAL: NODE_ENV must be development, test, or production');
  console.error('Current NODE_ENV:', process.env.NODE_ENV);
  console.error('Not starting server for safety.');
  process.exit(1);
}

const express = require('express');
// Simple cookie parser middleware (no external dependency)
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { verifyToken, requireRole, requireVerifiedEmail } = require('./auth/middleware-supabase');
const authRoutes = require('./auth/supabase-auth');
const recordsDAO = require('./db/records-supabase');
const auditDAO = require('./db/audit-supabase');
const newsDAO = require('./db/news');
const { OpenAI } = require('openai');
const fs = require('fs');
const path = require('path');

function createApp(options = {}) {
  const app = express();

  // Trust the first proxy hop (Vercel's edge) so req.ip resolves to the real
  // client via x-forwarded-for. Without this, express-rate-limit keys every
  // request behind a given Vercel edge node to the SAME bucket, so many real
  // users (e.g. students on shared networks in Gondar) collide into one
  // 20/min counter and lock each other out of sign-in. One hop only — trusting
  // the whole chain would let a client spoof x-forwarded-for to dodge limits.
  app.set('trust proxy', 1);

  // Rate limiters are created fresh per app so tests can override limits per-instance
  const maxAi = process.env.AI_RATE_LIMIT_MAX
    ? parseInt(process.env.AI_RATE_LIMIT_MAX)
    : 5;
  const aiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: maxAi,
    message: 'AI analysis rate limit exceeded. Please wait a moment and try again.'
  });

  const apiLimiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOW
      ? parseInt(process.env.RATE_LIMIT_WINDOW) * 60 * 1000
      : 1 * 60 * 1000,
    max: process.env.RATE_LIMIT_MAX
      ? parseInt(process.env.RATE_LIMIT_MAX)
      : 20,
    standardHeaders: true,
    legacyHeaders: false,
    // /auth/register has its own registerLimiter with a higher allowance.
    // Don't count registration traffic against the global apiLimiter
    // budget, or a fresh user trying to sign up gets blocked by login noise.
    //
    // ALSO exempt the two Google OAuth COMPLETION routes:
    //   GET  /auth/oauth-callback  — the spinner bridge page
    //   POST /auth/oauth-session   — the session handoff
    // These run AFTER the user has already authenticated with Google, so they
    // are not an abuse surface. They were the cause of "Google sign-in loads
    // forever": a user retrying a few times burned the 20/min budget, after
    // which the callback page itself returned plain-text "Too many requests"
    // instead of the spinner HTML — no JS ran, the #access_token sat unused,
    // and the page hung. /auth/google (which mints the OAuth URL) stays limited.
    // Check both relative (req.path) and original (req.originalUrl) paths
    // since express strips the mount prefix before middlewares see req.path.
    skip: (req) => {
      const p = req.path || '';
      const u = req.originalUrl || '';
      const isRegister = p === '/register' || p === '/auth/register' ||
             u === '/auth/register' || u.startsWith('/auth/register?');
      const isOAuthCallback = p === '/oauth-callback' || p === '/auth/oauth-callback' ||
             u === '/auth/oauth-callback' || u.startsWith('/auth/oauth-callback?');
      const isOAuthSession = p === '/oauth-session' || p === '/auth/oauth-session' ||
             u === '/auth/oauth-session' || u.startsWith('/auth/oauth-session?');
      return isRegister || isOAuthCallback || isOAuthSession;
    },
    message: 'Too many requests, please try again later.'
  });

// 1. Body parsing
// Vercel serverless rejects request bodies above ~4.5 MB at the edge with a
// plain-text 413 FUNCTION_PAYLOAD_TOO_LARGE response that's surfaced to
// users as a confusing "Internal server error". We cap the JSON body to
// 4 MB to match the practical Vercel limit, and let express return a clean
// 413 with a JSON error body that the frontend can present sensibly.
app.use(express.json({ limit: '4mb' }));

// Express's default PayloadTooLargeError handler returns HTML. Override it
// with a clean JSON error so the frontend can show a friendly message.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Image is too large for our server. Please use a smaller photo or describe your symptoms in text.'
    });
  }
  return next(err);
});
// Parse cookies manually
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(pair => {
      const [key, ...val] = pair.trim().split('=');
      req.cookies[key] = decodeURIComponent(val.join('='));
    });
  }
  next();
});

// 2. CORS - restricted to allowed origins
// '*' in ALLOWED_ORIGINS allows any origin (use only for trusted demos / previews).
// Production should set a comma-separated list of exact origins, e.g.
//   ALLOWED_ORIGINS=https://mediscan.vercel.app,https://mediscan.com
const ALLOW_ALL_ORIGINS = process.env.ALLOWED_ORIGINS === '*';
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:3001')
  .split(',')
  .map(o => o.trim())
  .filter(o => o && o !== '*');
// Vercel injects VERCEL_URL (per-deploy) and VERCEL_PROJECT_PRODUCTION_URL (stable alias).
// Auto-allowing them means a missing ALLOWED_ORIGINS cannot 500 the whole site,
// which is exactly how prod broke once already.
const vercelOrigins = [
  process.env.VERCEL_URL,
  process.env.VERCEL_PROJECT_PRODUCTION_URL,
  process.env.VERCEL_BRANCH_URL,
].filter(Boolean).map(u => `https://${u}`);
const effectiveOrigins = Array.from(new Set([...allowedOrigins, ...vercelOrigins]));
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like curl, Postman, server-to-server)
    if (!origin) return callback(null, true);
    // Explicit wildcard — accept any origin
    if (ALLOW_ALL_ORIGINS) return callback(null, true);
    // Exact match against allowlist (configured + auto-detected Vercel URLs)
    if (effectiveOrigins.includes(origin)) return callback(null, true);
    // Localhost on any port in non-production
    if (process.env.NODE_ENV !== 'production' && origin.includes('localhost:')) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use((req, res, next) => { res.vary('Origin'); next(); });

// 3. Security headers
// NOTE: 'unsafe-inline' required for single-file app with inline styles/scripts + CDN deps
// This is a deliberate security trade-off for the demo SPA; do NOT add to production apps without
// compensating controls (nonce-based CSP or build step to extract inline code).
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      'default-src': ["'self'"],
      'script-src':  ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com', 'unpkg.com', 'https://cdnjs.cloudflare.com', 'https://unpkg.com'],
      'script-src-elem':  ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com', 'unpkg.com', 'https://cdnjs.cloudflare.com', 'https://unpkg.com'],
      'script-src-attr':   ["'self'", "'unsafe-inline'"],
      'style-src':   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'https://fonts.googleapis.com'],
      'style-src-elem':    ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'https://fonts.googleapis.com', 'unpkg.com'],
      'font-src':    ["'self'", 'fonts.gstatic.com', 'https://fonts.gstatic.com'],
      'img-src':     ["'self'", 'data:', 'blob:', 'https:'],
      'connect-src': ["'self'"],
      'frame-src':   ["'none'"],
      'object-src':  ["'none'"],
      'base-uri':    ["'self'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// 5. CSRF protection - check Origin header for state-changing requests
const csrfProtection = (req, res, next) => {
  // Skip for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip in test mode
  if (process.env.NODE_ENV === 'test') {
    return next();
  }

  const origin = req.headers.origin;

  // Allow requests with no origin (like API clients/curl)
  if (!origin) {
    return next();
  }

  // Check if origin is in allowed list.
  // Use effectiveOrigins (configured + auto-detected Vercel URLs), the SAME
  // set the CORS layer uses at line ~118. They MUST stay in sync: if CORS
  // accepts an origin but CSRF rejects it, every state-changing POST 403s
  // while reads succeed — which is exactly how Google sign-in and email login
  // broke on production after the CORS-only fix in 6bbb040.
  const isAllowed = ALLOW_ALL_ORIGINS
    || effectiveOrigins.includes(origin)
    // Localhost on any port in non-production, mirroring the CORS callback.
    || (process.env.NODE_ENV !== 'production' && origin.includes('localhost:'));

  if (!isAllowed) {
    console.warn(`CSRF rejection: Origin ${origin} not in allowed list`);
    return res.status(403).json({ error: 'Forbidden: Invalid origin' });
  }

  next();
};

// 6. Static file serving
// On Vercel serverless the project root isn't included in the function bundle,
// so express.static(path.join(__dirname)) sees an empty directory and every
// request 404s. We work around this by serving an explicit allowlist of
// assets the app actually needs (PNGs, modules, locales, etc.) and letting
// unknown paths fall through to the API routes.
const publicDir = path.join(__dirname);

// Reject obvious path-traversal attempts BEFORE the static middleware sees
// them. express.static and Express itself will normalize `..` segments, but
// doing the check up-front keeps any future static source from being able
// to read files outside the project root.
app.use((req, res, next) => {
  const decoded = decodeURIComponent(req.path || '');
  if (decoded.includes('..') || decoded.includes('\0')) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  next();
});

app.use(express.static(publicDir, {
  // Don't serve dotfiles (e.g. .env) even if they exist in the project root
  dotfiles: 'deny',
  // Don't generate a directory index
  index: false,
  // No Last-Modified; keep responses cacheable for 5 min
  maxAge: '5m'
}));

const STATIC_CONTENT_TYPES = {
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg':  'image/svg+xml',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico':  'image/x-icon',
  '.html': 'text/html; charset=utf-8'
};

// Whitelist of root-relative file paths the app is allowed to fetch.
// Add new static assets here when they're introduced — keeps us off
// any "list a directory" path-traversal surface.
const STATIC_ASSET_WHITELIST = new Set([
  '/male-front.png',
  '/male-back.png',
  '/female-front.png',
  '/female-back.png',
  '/reference-male.png',
  '/hospital-map.css',
  '/hospital-map.js',
  '/timeline.js',
  '/modules/body-heatmap.js',
  '/modules/body-heatmap-muscles.js',
  '/modules/heatmap-switcher.js',
  '/modules/heatmap-state.js',
  '/modules/demo-body-heatmap-simple.js',
  '/modules/translations.js',
  '/locales/am.json'
]);

app.get('/modules/:file', (req, res, next) => {
  const safe = String(req.params.file || '').replace(/[^a-zA-Z0-9._-]/g, '');
  if (!safe) return next();
  const reqPath = '/modules/' + safe;
  if (!STATIC_ASSET_WHITELIST.has(reqPath)) return next();
  const filePath = path.join(__dirname, 'modules', safe);
  if (!fs.existsSync(filePath)) return next();
  res.set('Content-Type', STATIC_CONTENT_TYPES['.js']);
  res.set('Cache-Control', 'public, max-age=300');
  return res.sendFile(filePath);
});

app.get('/locales/:file', (req, res, next) => {
  const safe = String(req.params.file || '').replace(/[^a-zA-Z0-9._-]/g, '');
  if (!safe) return next();
  const reqPath = '/locales/' + safe;
  if (!STATIC_ASSET_WHITELIST.has(reqPath)) return next();
  const filePath = path.join(__dirname, 'locales', safe);
  if (!fs.existsSync(filePath)) return next();
  res.set('Content-Type', STATIC_CONTENT_TYPES['.json']);
  res.set('Cache-Control', 'public, max-age=300');
  return res.sendFile(filePath);
});

app.get(/^\/(male-(front|back)\.png|female-(front|back)\.png|reference-male\.png|hospital-map\.(css|js)|timeline\.js)$/, (req, res) => {
  const reqPath = req.path;
  if (!STATIC_ASSET_WHITELIST.has(reqPath)) return res.status(404).end();
  const filePath = path.join(publicDir, reqPath);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  const ext = path.extname(reqPath).toLowerCase();
  res.set('Content-Type', STATIC_CONTENT_TYPES[ext] || 'application/octet-stream');
  res.set('Cache-Control', 'public, max-age=300');
  return res.sendFile(filePath);
});

// 6. Request logging (after helmet and static)
app.use((req, res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
  }
  next();
});

// 7. Mount auth routes with rate limiting and CSRF protection.
// apiLimiter skips /auth/register; that route has its own registerLimiter.
app.use('/auth', csrfProtection, apiLimiter, authRoutes);

// 8. Mount timeline routes with rate limiting and auth
app.use('/timeline', apiLimiter, verifyToken, requireVerifiedEmail, require('./timeline'));

// 9. Mount heatmap API (requires authentication + verified email)
app.use('/api/heatmap', verifyToken, requireVerifiedEmail, require('./api/heatmap'));

// 10. Mount profile API (requires authentication + verified email)
app.use('/api/profile', verifyToken, requireVerifiedEmail, require('./api/profile'));

// 11. Mount appointments API (requires authentication + verified email)
app.use('/api/appointments', verifyToken, requireVerifiedEmail, require('./api/appointments'));

// 12. Mount doctors API (requires authentication + verified email)
app.use('/api/doctors', verifyToken, requireVerifiedEmail, require('./api/doctors'));

// 13. Mount medicine-reminders API (requires authentication + verified email)
app.use('/api/medicine-reminders', verifyToken, requireVerifiedEmail, require('./api/medicine-reminders'));

// ===== Response cache - keyed by symptom hash, expires after 1 hour =====
const responseCache = new Map();
const MAX_CACHE_SIZE = 500;
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

function getCacheKey(symptoms, bodyArea, lang, bodyRegions) {
  const crypto = require('crypto');
  // bodyRegions is part of the key because the heatmap path often leaves bodyArea
  // empty, so without it two users with identical symptom text but different
  // clicked regions would share a cached diagnosis (privacy leak). Name is
  // omitted to stay stable across i18n.
  const regionKey = (Array.isArray(bodyRegions) ? bodyRegions : [])
    .filter(r => r && typeof r === 'object')
    .map(r => ({ area: r.area, intensity: r.intensity }))
    .sort((a, b) => String(a.area || '').localeCompare(String(b.area || '')))
    .map(r => JSON.stringify(r))
    .join('|');
  return crypto.createHash('md5').update(`${symptoms}:${bodyArea}:${lang || 'en'}:${regionKey}`).digest('hex');
}

function getCached(key) {
  const entry = responseCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    responseCache.delete(key);
    return null;
  }
  return entry.data;
}

function setCached(key, data) {
  // Prevent memory exhaustion - evict oldest if at limit
  if (responseCache.size >= MAX_CACHE_SIZE) {
    const firstKey = responseCache.keys().next().value;
    responseCache.delete(firstKey);
  }
  responseCache.set(key, { data, expires: Date.now() + CACHE_TTL });
}

// ===== Ollama (Local, Free) =====
// Overridable so tests can point it at a dead port. Without that, a developer
// with Ollama running gets a different fallback chain than CI does: the chain
// ends at Ollama instead of demo, and the timeout tests fail. Every other
// provider already reads its endpoint or key from the environment.
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
let ollamaAvailable = false;

async function checkOllama() {
  if (process.env.VERCEL) {
    console.log('Ollama check skipped on Vercel');
    return;
  }
  try {
    const response = await fetch(`${OLLAMA_URL}/api/tags`);
    if (response.ok) {
      const data = await response.json();
      ollamaAvailable = true;
      if (process.env.NODE_ENV !== 'production') {
        console.log('Ollama available with models:', data.models?.map(m => m.name).join(', '));
      }
    }
  } catch (e) {
    if (process.env.NODE_ENV !== 'production') {
      console.log('Ollama not running. Start with: ollama serve');
    }
  }
}
checkOllama();

// ===== AI Client Initialization =====
const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;
const groq = process.env.GROQ_API_KEY ? new OpenAI({ apiKey: process.env.GROQ_API_KEY, baseURL: 'https://api.groq.com/openai/v1' }) : null;
const nvidia = process.env.NVIDIA_API_KEY ? new OpenAI({ apiKey: process.env.NVIDIA_API_KEY, baseURL: 'https://integrate.api.nvidia.com/v1' }) : null;

const { describeImage } = require('./modules/geminiVisionClient.js');

// ===== Model Configuration =====
const MODEL_PRIORITY = ['groq', 'nvidia', 'ollama', 'demo'];

// Model IDs, kept in one place. Every value here was called live on 2026-10-18.
// The previous IDs (llama-3.3-70b-versatile, gemma-7b-it, and NVIDIA's
// openai/gpt-oss-120b) are all retired upstream and return model_not_found,
// model_decommissioned, or HTTP 410. Do not restore them.
const GROQ_MODEL = 'openai/gpt-oss-120b';
const NVIDIA_MODEL = 'openai/gpt-oss-20b';
const GROQ_NEWS_MODEL = 'openai/gpt-oss-20b';

const MODEL_CAPABILITIES = {
  nvidia: { supportsImages: false },
  groq: { supportsImages: false },
  ollama: { supportsImages: false },
  demo: { supportsImages: false }
};

const DAILY_LIMITS = {
  nvidia: 10000,
  groq: 14400,
  demo: Infinity
};

let rateLimits = {
  resetTime: getNextMidnight(),
  nvidia: 0,
  groq: 0,
  demo: 0
};

function getNextMidnight() {
  const nextMidnight = new Date();
  nextMidnight.setHours(24, 0, 0, 0);
  return nextMidnight.getTime();
}

function loadRateLimits() {
  if (Date.now() > rateLimits.resetTime) {
    rateLimits = { resetTime: getNextMidnight(), groq: 0, nvidia: 0, demo: 0 };
  }
  return rateLimits;
}

function saveRateLimits(limits) {
  // No-op for Vercel
}

function isModelAvailable(model) {
  if (model === 'ollama') return ollamaAvailable;
  if (Date.now() > rateLimits.resetTime) {
    rateLimits = { resetTime: getNextMidnight(), groq: 0, nvidia: 0, demo: 0 };
  }
  return rateLimits[model] < DAILY_LIMITS[model] || DAILY_LIMITS[model] === Infinity;
}

function incrementModel(model) {
  rateLimits[model]++;
}

function exhaustModel(model) {
  rateLimits[model] = DAILY_LIMITS[model];
}

// ===== Mock Data =====
const MOCK_CONDITIONS = [
  {
    primaryCondition: "Contact Dermatitis",
    confidence: 78, severity: "low",
    subtitle: "Skin condition / allergic reaction",
    description: "A common skin reaction that occurs when your skin comes into contact with an irritant or allergen. The skin becomes inflamed, causing redness, itching, and sometimes blistering.",
    symptoms: ["Red, inflamed skin", "Itching or burning sensation", "Dry, cracked skin", "Blisters in severe cases"],
    nextSteps: ["Identify and avoid the triggering substance", "Apply cool, wet compresses to affected areas", "Use over-the-counter hydrocortisone cream", "Consider oral antihistamines for itching"],
    urgentSigns: "Seek emergency care if you experience difficulty breathing, swelling of face/lips, or widespread rash with fever.",
    alternatives: [{ name: "Eczema (Atopic Dermatitis)", confidence: 45 }, { name: "Psoriasis", confidence: 28 }, { name: "Heat Rash", confidence: 15 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  },
  {
    primaryCondition: "Seasonal Allergies",
    confidence: 85, severity: "low",
    subtitle: "Allergic rhinitis / immune response",
    description: "An allergic response to pollen, dust, or other airborne allergens. Your immune system overreacts to these harmless substances, causing inflammation in your nasal passages and sinuses.",
    symptoms: ["Sneezing and runny nose", "Itchy, watery eyes", "Nasal congestion", "Post-nasal drip"],
    nextSteps: ["Limit outdoor exposure during high pollen days", "Use saline nasal rinses", "Try over-the-counter antihistamines", "Keep windows closed during peak pollen season"],
    urgentSigns: "Seek emergency care if you develop wheezing, shortness of breath, or facial/throat swelling.",
    alternatives: [{ name: "Common Cold", confidence: 35 }, { name: "Sinus Infection", confidence: 22 }, { name: "Non-allergic Rhinitis", confidence: 12 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  },
  {
    primaryCondition: "Tension Headache",
    confidence: 82, severity: "low",
    subtitle: "Primary headache disorder",
    description: "The most common type of headache, often caused by stress, poor posture, or eye strain.",
    symptoms: ["Dull, aching head pain", "Pressure across forehead or sides of head", "Tenderness in scalp or neck muscles", "Sensitivity to light or noise"],
    nextSteps: ["Practice stress management techniques like deep breathing", "Apply heat or cold to tense muscles", "Take over-the-counter pain relievers", "Improve posture and ergonomics"],
    urgentSigns: "Seek immediate care for sudden severe headache, headache with fever/stiff neck, or after head injury.",
    alternatives: [{ name: "Migraine", confidence: 48 }, { name: "Sinus Headache", confidence: 25 }, { name: "Cluster Headache", confidence: 10 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  },
  {
    primaryCondition: "Viral Upper Respiratory Infection",
    confidence: 88, severity: "medium",
    subtitle: "Common cold / viral infection",
    description: "A viral infection of your nose and throat, commonly known as a cold. Hundreds of viruses can cause these symptoms, with rhinoviruses being most common.",
    symptoms: ["Runny or stuffy nose", "Sore throat", "Mild cough", "Low-grade fever", "Fatigue"],
    nextSteps: ["Get plenty of rest and stay hydrated", "Use saline nasal spray for congestion", "Take acetaminophen for fever/aches", "Gargle warm salt water for sore throat"],
    urgentSigns: "Seek care for high fever lasting more than 3 days, difficulty breathing, or symptoms lasting more than 10 days.",
    alternatives: [{ name: "Influenza", confidence: 42 }, { name: "COVID-19", confidence: 28 }, { name: "Strep Throat", confidence: 15 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  },
  {
    primaryCondition: "Gastroesophageal Reflux (GERD)",
    confidence: 72, severity: "medium",
    subtitle: "Digestive disorder / acid reflux",
    description: "A digestive condition where stomach acid frequently flows back into the tube connecting your mouth and stomach.",
    symptoms: ["Heartburn after eating", "Chest pain or discomfort", "Difficulty swallowing", "Regurgitation of food or sour liquid"],
    nextSteps: ["Avoid trigger foods (spicy, fatty, acidic)", "Eat smaller meals and do not lie down after eating", "Elevate head of bed 6-8 inches", "Try over-the-counter antacids"],
    urgentSigns: "Seek immediate care for chest pain with arm pain, vomiting blood, or black tarry stools.",
    alternatives: [{ name: "Gastritis", confidence: 38 }, { name: "Peptic Ulcer", confidence: 25 }, { name: "Gallbladder Issues", confidence: 12 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  },
  {
    primaryCondition: "Conjunctivitis (Pink Eye)",
    confidence: 80, severity: "low",
    subtitle: "Eye infection / inflammation",
    description: "Inflammation of the conjunctiva, the thin clear tissue that lies over the white part of the eye and lines the inside of the eyelid.",
    symptoms: ["Red or pink eye color", "Itching or burning sensation", "Watery or thick discharge", "Sensitivity to light"],
    nextSteps: ["Avoid touching or rubbing eyes", "Use warm compresses to loosen crust", "Artificial tears for comfort", "Practice good hand hygiene"],
    urgentSigns: "Seek immediate care for eye pain, vision changes, or severe sensitivity to light.",
    alternatives: [{ name: "Dry Eye Syndrome", confidence: 35 }, { name: "Allergic Eye Reaction", confidence: 28 }, { name: "Corneal Abrasion", confidence: 8 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  },
  {
    primaryCondition: "Anxiety Attack (Panic Attack)",
    confidence: 76, severity: "medium",
    subtitle: "Mental health / anxiety disorder",
    description: "A sudden episode of intense fear that triggers severe physical reactions when there is no real danger or apparent cause.",
    symptoms: ["Rapid heart rate", "Sweating and trembling", "Shortness of breath", "Chest pain or tightness", "Fear of losing control"],
    nextSteps: ["Practice deep breathing (4-7-8 technique)", "Ground yourself with 5-4-3-2-1 technique", "Find a quiet space to rest", "Consider therapy or counseling"],
    urgentSigns: "Call emergency services if chest pain is severe, or if this is your first episode and you are unsure it is anxiety.",
    alternatives: [{ name: "Hyperventilation Syndrome", confidence: 42 }, { name: "Heart Arrhythmia", confidence: 18 }, { name: "Thyroid Issue", confidence: 12 }],
    disclaimer: "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
  }
];

function getMockDiagnosis(symptoms, bodyArea) {
  const s = (symptoms || '').toLowerCase();
  const b = (bodyArea || '').toLowerCase();
  if (b.includes('eye') || s.includes('eye')) return MOCK_CONDITIONS[5];
  if (b.includes('skin') || s.includes('rash') || s.includes('itch')) return MOCK_CONDITIONS[0];
  if (b.includes('nose') || b.includes('throat') || s.includes('sneeze')) return MOCK_CONDITIONS[1];
  if (b.includes('head') || s.includes('headache') || s.includes('migraine')) return MOCK_CONDITIONS[2];
  if (b.includes('chest') || s.includes('heart') || s.includes('anxiety') || s.includes('panic')) return MOCK_CONDITIONS[6];
  if (s.includes('stomach') || s.includes('acid') || s.includes('heartburn')) return MOCK_CONDITIONS[4];
  return MOCK_CONDITIONS[3];
}

function extractJSON(raw) {
  raw = raw.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim();
  try {
    return JSON.parse(raw);
  } catch (_) { /* fall through to balanced-brace walk */ }

  // A naive raw.indexOf('{')..raw.lastIndexOf('}') slice concatenates prose
  // braces (e.g. "see {below} for details: {<real json>}") into the parsed
  // string. Walk the source counting braces while respecting string literals
  // and return the first balanced object that parses as valid JSON.
  const candidates = findBalancedObjects(raw);
  const tryParse = (s) => {
    try { return [JSON.parse(s), null]; } catch (e) { /* try repair */ }
    const fixed = s
      .replace(/,\s*([}\]])/g, '$1')
      .replace(/[\x00-\x1F\x7F]/g, ' ')
      .replace(/'/g, '"');
    try { return [JSON.parse(fixed), null]; } catch (e) { return [null, e]; }
  };
  for (const c of candidates) {
    const [obj] = tryParse(c);
    if (obj) return obj;
  }

  if (candidates.length === 0) {
    console.error('No JSON found in response:', raw.slice(0, 200));
    throw new Error('No JSON found in AI response');
  }
  console.error('JSON parse failed for all candidates');
  console.error('Raw response:', raw.slice(0, 500));
  throw new Error('AI returned malformed JSON. Please try again.');
}

function findBalancedObjects(s) {
  const out = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let escape = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (escape) { escape = false; continue; }
      if (c === '\\') { escape = true; continue; }
      if (c === '"') { inStr = false; }
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0 && start !== -1) { out.push(s.slice(start, i + 1)); start = -1; }
      if (depth < 0) { depth = 0; start = -1; }
    }
  }
  return out;
}

// ===== Response Normalizer =====
// Different AI models return different JSON shapes. The frontend expects a
// canonical schema. This function maps any reasonable response into it,
// with safe fallbacks for any missing required fields. If the response is
// too broken, returns a demo-style diagnosis so the UI never goes blank.
function normalizeAIResponse(raw) {
  if (!raw || typeof raw !== 'object') {
    return getMockDiagnosis('', '');
  }

  // Coerce a field that may arrive as a plain string, an object like
  // {level/value/severity: "high"}, an array (take first), or null/undefined.
  // Returning a string lets the existing toLowerCase/allow-list check work
  // instead of stringifying an object to "[object object]" and silently
  // falling through to the keyword-inference branch (which defaults to low).
  const coerceScalar = (v) => {
    if (v == null) return '';
    if (typeof v === 'string') return v;
    if (Array.isArray(v)) return v.length ? coerceScalar(v[0]) : '';
    if (typeof v === 'object') {
      const cand = v.level || v.value || v.severity || v.label || v.name;
      return typeof cand === 'string' ? cand : '';
    }
    return String(v);
  };

  const r = { ...raw };
  // symptoms: handle both string arrays and object arrays (e.g. {name, severity})
  const symptomsArr = Array.isArray(r.symptoms) ? r.symptoms.map(s => typeof s === 'string' ? s : (s.name || s.symptom || String(s))) : [];
  const possibleConditions = Array.isArray(r.possible_conditions) ? r.possible_conditions
    : Array.isArray(r.possibleCauses) ? r.possibleCauses
    : Array.isArray(r.conditions) ? r.conditions
    : Array.isArray(r.differential) ? r.differential
    : Array.isArray(r.diagnoses) ? r.diagnoses
    : (typeof r.diagnosis === 'string' ? [r.diagnosis] : [])
    ;
  const recommendedActions = Array.isArray(r.recommended_actions) ? r.recommended_actions
    : Array.isArray(r.recommendedActions) ? r.recommendedActions
    : Array.isArray(r.actions) ? r.actions
    : Array.isArray(r.recommendations) ? r.recommendations
    : [];

  // primaryCondition: prefer canonical, else first possible_condition, else diagnosis, else "Undetermined condition"
  if (!r.primaryCondition) {
    if (typeof r.condition === 'string' && r.condition.trim()) {
      r.primaryCondition = r.condition.trim();
    } else if (possibleConditions.length > 0) {
      const first = possibleConditions[0];
      r.primaryCondition = (typeof first === 'string' ? first : (first.name || first.condition || String(first))).trim();
    } else if (symptomsArr.length > 0) {
      const firstSymptom = symptomsArr[0];
      r.primaryCondition = 'Possible ' + (typeof firstSymptom === 'string' ? firstSymptom : String(firstSymptom)).trim();
    } else {
      r.primaryCondition = 'Undetermined condition';
    }
  }

  // confidence: number 55-92
  let conf = Number(r.confidence);
  if (!Number.isFinite(conf)) conf = 65;
  r.confidence = Math.min(92, Math.max(55, Math.round(conf)));

  // severity: low | medium | high
  const sev = coerceScalar(r.severity).toLowerCase();
  if (['low', 'medium', 'high'].includes(sev)) {
    r.severity = sev;
  } else if (r.urgency != null && coerceScalar(r.urgency)) {
    const u = coerceScalar(r.urgency).toLowerCase();
    if (u.includes('high') || u.includes('urgent') || u.includes('severe')) r.severity = 'high';
    else if (u.includes('moderate') || u.includes('medium')) r.severity = 'medium';
    else r.severity = 'low';
  } else {
    // Infer severity from condition + symptoms when AI didn't supply one.
    // Default to "low" but escalate to "high" for clearly urgent conditions.
    const HIGH_SEVERITY_KEYWORDS = [
      'myocardial infarction', 'heart attack', 'stroke', 'anaphylaxis', 'anaphylactic',
      'pulmonary embolism', 'sepsis', 'meningitis', ' ectopic ', 'aortic dissection',
      'subarachnoid hemorrhage', 'intracranial hemorrhage', 'cardiac arrest', 'respiratory failure',
      'testicular torsion', 'rhabdomyolysis', 'diabetic ketoacidosis', 'status epilepticus'
    ];
    const MEDIUM_SEVERITY_KEYWORDS = [
      'pneumonia', 'bronchitis', 'asthma', 'migraine', 'concussion', 'gastritis', 'ulcer',
      'appendicitis', 'cellulitis', 'diverticulitis', 'pancreatitis', 'kidney stone',
      'deep vein thrombosis', 'dvt', 'atrial fibrillation', 'arrhythmia', 'hernia',
      'fracture', 'sprain', 'burn', 'concussion', 'food poisoning', 'urinary tract infection',
      'sinus infection', 'sinusitis'
    ];
    const pcLower = String(r.primaryCondition || '').toLowerCase();
    const allText = (pcLower + ' ' + symptomsArr.join(' ').toLowerCase());
    if (HIGH_SEVERITY_KEYWORDS.some(k => allText.includes(k))) {
      r.severity = 'high';
    } else if (MEDIUM_SEVERITY_KEYWORDS.some(k => allText.includes(k))) {
      r.severity = 'medium';
    } else {
      r.severity = 'low';
    }
  }

  // subtitle
  if (!r.subtitle) {
    r.subtitle = r.severity === 'high' ? 'Requires prompt medical attention' : 'Common presentation';
  }

  // description
  if (!r.description || !String(r.description).trim()) {
    if (r.assessment) {
      r.description = String(r.assessment).trim();
    } else if (symptomsArr.length > 0) {
      r.description = `Based on the symptoms described (${symptomsArr.slice(0, 3).join(', ')}), this presentation is consistent with ${r.primaryCondition}.`;
    } else {
      r.description = `This analysis suggests ${r.primaryCondition}. A licensed physician should be consulted for diagnosis and treatment.`;
    }
  }

  // symptoms
  if (!Array.isArray(r.symptoms) || r.symptoms.length === 0) {
    r.symptoms = [];
  }

  // nextSteps: prefer canonical, else recommended_actions
  if (!Array.isArray(r.nextSteps) || r.nextSteps.length === 0) {
    r.nextSteps = recommendedActions.slice(0, 4).map(step => typeof step === 'string' ? step : String(step));
    if (r.nextSteps.length === 0) {
      r.nextSteps = [
        'Monitor your symptoms and note any changes',
        'Stay hydrated and get adequate rest',
        'Consult a licensed physician for proper evaluation',
        'Seek urgent care if symptoms worsen'
      ];
    }
  } else {
    r.nextSteps = r.nextSteps.map(step => {
      if (typeof step === 'string') return step;
      if (typeof step === 'object' && step !== null) {
        // Try common property names for step text
        return step.text || step.description || step.step || step.action || step.recommendation || step.title || step.name || step.advice || JSON.stringify(step).slice(0, 100);
      }
      return String(step);
    });
  }

  // urgentSigns
  if (!r.urgentSigns || !String(r.urgentSigns).trim()) {
    r.urgentSigns = r.severity === 'high'
      ? 'Seek immediate medical care if you experience severe pain, difficulty breathing, confusion, or rapidly worsening symptoms.'
      : 'Seek emergency care if you develop severe pain, high fever, difficulty breathing, or sudden worsening of symptoms.';
  }

  // alternatives: prefer canonical, else map possible_conditions[1..]
  if (!Array.isArray(r.alternatives) || r.alternatives.length === 0) {
    const altsFromPC = possibleConditions.slice(1).map((name, i) => {
      const condName = typeof name === 'string' ? name : (name.name || name.condition || String(name));
      return {
        name: condName.trim(),
        confidence: Math.max(15, r.confidence - 20 - i * 10)
      };
    });
    r.alternatives = altsFromPC.slice(0, 3);
    if (r.alternatives.length === 0) {
      r.alternatives = [
        { name: 'Other common condition', confidence: 35 },
        { name: 'Less likely alternative', confidence: 18 },
        { name: 'Rare presentation', confidence: 8 }
      ];
    }
  } else {
    // ensure each alternative has name + confidence
    r.alternatives = r.alternatives.map((a, i) => {
      if (typeof a === 'string') {
        return { name: a, confidence: Math.max(10, r.confidence - 15 - i * 10) };
      }
      const condName = typeof a.name === 'string' ? a.name : (a.name?.name || a.condition || String(a.name || `Alternative ${i + 1}`));
      return {
        name: condName.trim(),
        confidence: Math.min(95, Math.max(10, Number(a.confidence) || Math.max(10, r.confidence - 15 - i * 10)))
      };
    });
  }

  // disclaimer
  if (!r.disclaimer || !String(r.disclaimer).trim()) {
    r.disclaimer = 'This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician.';
  }

  // Strip alternative-schema noise fields so the response shape is clean
  const noiseKeys = ['possible_conditions', 'possibleCauses', 'differential', 'conditions', 'diagnoses',
                     'recommended_actions', 'recommendedActions', 'actions', 'recommendations',
                     'condition', 'assessment', 'urgency', 'diagnosis'];
  for (const k of noiseKeys) delete r[k];

  return r;
}

// ===== Ollama (Secondary - Local, Free) =====
async function analyzeWithOllama(prompt) {
  if (!ollamaAvailable) throw new Error('Ollama not available');
  const systemPrompt = `You are a medical AI assistant. You MUST respond with ONLY a valid JSON object matching this exact structure:
{
  "primaryCondition": "string - the main condition name",
  "confidence": number between 55-92,
  "severity": "low" | "medium" | "high",
  "subtitle": "string - brief medical category",
  "description": "string - 2-3 sentences explaining the condition",
  "symptoms": ["array", "of", "symptoms"],
  "nextSteps": ["array", "of", "recommendations"],
  "urgentSigns": "string - when to seek emergency care",
  "alternatives": [
    {"name": "string", "confidence": number},
    {"name": "string", "confidence": number},
    {"name": "string", "confidence": number}
  ],
  "disclaimer": "This AI analysis is for educational purposes only and does not constitute medical advice. Please consult a licensed physician."
}

Rules:
- Respond ONLY with the JSON object
- No markdown, NO backticks, NO explanations
- severity MUST be exactly: low, medium, or high
- confidence MUST be a number between 55-92`;

  const response = await fetch(`${OLLAMA_URL}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'llama3.2',
      prompt: systemPrompt + '\n\n' + prompt + '\n\nRemember: Respond ONLY with valid JSON, no markdown, no backticks.',
      stream: false,
      options: { temperature: 0.2, num_predict: 2048 }
    })
  });
  if (!response.ok) throw new Error('Ollama request failed');
  const data = await response.json();
  try {
    const result = extractJSON(data.response);
    if (!result.primaryCondition || !result.severity) {
      throw new Error('Ollama response missing required fields');
    }
    if (!['low', 'medium', 'high'].includes(result.severity)) {
      result.severity = 'medium';
    }
    return result;
  } catch (e) {
    if (process.env.NODE_ENV !== 'production') {
      console.log('Ollama returned invalid JSON, falling back to demo data');
    }
    throw new Error('Ollama JSON parse failed: ' + e.message);
  }
}

async function chatWithOllama(prompt) {
  if (!ollamaAvailable) throw new Error('Ollama not available');
  const response = await fetch(`${OLLAMA_URL}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'llama3.2',
      prompt: prompt,
      stream: false,
      options: { temperature: 0.7 }
    })
  });
  if (!response.ok) throw new Error('Ollama chat failed');
  const data = await response.json();
  return data.response.trim();
}

// ===== Provider timeouts =====
// Groq answers in ~2s. NVIDIA's surviving text models are reasoning models that
// need ~13s. Worst case is vision (8s) + Groq (6s) + NVIDIA (20s) = 34s, which
// must stay under the maxDuration in vercel.json (45s) or the function is
// edge-killed with a 504 before the chain ever reaches demo mode.
// tests/ai-model-config.test.js guards that relationship.
const GROQ_TIMEOUT_MS = 6000;
const NVIDIA_TIMEOUT_MS = 20000;

// Shared deadline for news generation. One 20s budget covers both providers, so
// a slow one cannot run the request past the Vercel maxDuration before the
// result is saved. This matters more than it looks: the save happens AFTER
// generation, so an unbounded call means the cache never fills and every
// request pays the full cost again.
const NEWS_AI_TIMEOUT_MS = 20000;
// The news array needs room for the JSON plus the model's reasoning tokens, but
// 10000 was wasteful. 4000 keeps the reasoning models from returning empty
// content while cutting generation time.
const NEWS_MAX_TOKENS = 4000;

// ===== Groq (Primary) =====

async function analyzeWithGroq(prompt) {
  if (!groq) throw new Error('Groq not configured');
  if (process.env.NODE_ENV !== 'production') {
    console.log('Groq Request:', {
      model: GROQ_MODEL,
      promptLength: prompt?.length
    });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GROQ_TIMEOUT_MS);
  try {
    const response = await groq.chat.completions.create({
      model: GROQ_MODEL,
      temperature: 0.2,
      max_tokens: 4096,
      messages: [
        { role: 'system', content: 'You are a medical AI assistant. Respond ONLY with valid JSON. No markdown formatting, no backticks, no explanations.' },
        { role: 'user', content: prompt }
      ]
    }, { signal: controller.signal });

    const responseText = response.choices[0].message.content;
    if (process.env.NODE_ENV !== 'production') {
      console.log('Groq Response:', { length: responseText.length, model: GROQ_MODEL });
    }
    return extractJSON(responseText);
  } catch (error) {
    if (controller.signal.aborted) {
      console.error('Groq timeout ' + GROQ_TIMEOUT_MS + 'ms');
      throw new Error('Groq timeout after ' + GROQ_TIMEOUT_MS + 'ms');
    }
    console.error('Groq Error Details:', {
      message: error.message,
      status: error.status,
      details: error.cause
    });
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ===== NVIDIA (Secondary) =====
async function analyzeWithNvidia(prompt) {
  if (!nvidia) throw new Error('NVIDIA not configured');
  if (process.env.NODE_ENV !== 'production') {
    console.log('NVIDIA Request:', {
      model: NVIDIA_MODEL,
      promptLength: prompt?.length
    });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NVIDIA_TIMEOUT_MS);
  try {
    const response = await nvidia.chat.completions.create({
      model: NVIDIA_MODEL,
      temperature: 0.2,
      max_tokens: 4096,
      messages: [
        { role: 'system', content: 'You are a medical AI assistant. Respond ONLY with valid JSON. No markdown formatting, no backticks, no explanations.' },
        { role: 'user', content: prompt }
      ]
    }, { signal: controller.signal });

    const responseText = response.choices[0].message.content;
    if (process.env.NODE_ENV !== 'production') {
      console.log('NVIDIA Response:', { length: responseText.length, model: NVIDIA_MODEL });
    }
    return extractJSON(responseText);
  } catch (error) {
    if (controller.signal.aborted) {
      console.error('NVIDIA timeout ' + NVIDIA_TIMEOUT_MS + 'ms');
      throw new Error('NVIDIA timeout after ' + NVIDIA_TIMEOUT_MS + 'ms');
    }
    console.error('NVIDIA Error Details:', {
      message: error.message,
      status: error.status,
      details: error.cause
    });
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

// ===== Facility Recommendation =====
function recommendFacilities(severity, condition) {
  let hospitals = [];
  try {
    const hospitalData = fs.readFileSync(path.join(__dirname, 'hospitals-gondar.json'), 'utf8');
    hospitals = JSON.parse(hospitalData);
  } catch (error) {
    console.error('Failed to load hospital data:', error);
    return [];
  }

  const severityPriority = {
    high: ['hospital', 'health_center', 'clinic', 'pharmacy'],
    medium: ['health_center', 'hospital', 'clinic', 'pharmacy'],
    low: ['clinic', 'health_center', 'hospital', 'pharmacy']
  };

  const priorityOrder = severityPriority[severity] || severityPriority.low;

  const sorted = hospitals.sort((a, b) => {
    const aPriority = priorityOrder.indexOf(a.type);
    const bPriority = priorityOrder.indexOf(b.type);
    if (aPriority !== bPriority) return aPriority - bPriority;
    const a247 = a.hours === '24/7';
    const b247 = b.hours === '24/7';
    if (a247 && !b247) return -1;
    if (!a247 && b247) return 1;
    return 0;
  });

  return sorted.slice(0, 3).map(h => ({
    name: h.name,
    type: h.type,
    address: h.address,
    phone: h.phone,
    hours: h.hours,
    specialties: h.specialties,
    lat: h.lat,
    lng: h.lng
  }));
}

// ===== Translation helper (MyMemory Translation API) =====
// The AI model always responds in English (where it is strongest and most
// consistent). For non-English UI languages we run the response values
// through MyMemory so the result card renders in the user's locale.
// MyMemory's anonymous tier: 5,000 words/day per source IP, no key required.
// Quality varies (it uses multiple backends) but is solid for short medical
// strings. Falls back to untranslated English if the call fails or the daily
// quota is exhausted, so the demo never breaks because of translation issues.

const LOCALE_TO_MYMEMORY = { en: 'en', am: 'am', om: 'om', ti: 'ti' };

async function translateText(text, targetLang) {
  if (!text || !targetLang || targetLang === 'en') return text;
  try {
    const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(text)}&langpair=en|${encodeURIComponent(targetLang)}`;
    const response = await fetch(url);
    if (!response.ok) {
      console.error('MyMemory API error:', response.status);
      return text;
    }
    const data = await response.json();
    const status = data?.responseStatus;
    const translated = data?.responseData?.translatedText;
    if (status === 200 && translated) {
      return translated;
    }
    // 403/429 mean daily quota hit or rate limited — log once, return original
    if (status === 403 || status === 429) {
      console.warn(`MyMemory quota/rate limit hit (status ${status}) — returning untranslated text`);
    } else if (status >= 400) {
      console.error(`MyMemory translation error (status ${status}):`, data?.responseDetails || '');
    }
    return text;
  } catch (err) {
    console.error('MyMemory fetch failed:', err.message);
    return text;
  }
}

async function translateResult(result, lang) {
  if (!lang || lang === 'en') return result;

  const target = LOCALE_TO_MYMEMORY[lang] || lang;
  try {
    const translated = { ...result };
    if (result.primaryCondition) translated.primaryCondition = await translateText(result.primaryCondition, target);
    if (result.subtitle)         translated.subtitle         = await translateText(result.subtitle, target);
    if (result.description)      translated.description      = await translateText(result.description, target);
    if (result.urgentSigns)      translated.urgentSigns      = await translateText(result.urgentSigns, target);
    if (result.disclaimer)       translated.disclaimer       = await translateText(result.disclaimer, target);
    if (Array.isArray(result.symptoms)) {
      translated.symptoms = await Promise.all(result.symptoms.map(s => translateText(s, target)));
    }
    if (Array.isArray(result.nextSteps)) {
      translated.nextSteps = await Promise.all(result.nextSteps.map(s => translateText(s, target)));
    }
    if (Array.isArray(result.alternatives)) {
      translated.alternatives = await Promise.all(result.alternatives.map(async (alt) => ({
        ...alt,
        name: await translateText(alt.name, target)
      })));
    }
    translated.translatedTo = lang; // marker for the frontend
    return translated;
  } catch (err) {
    console.error('translateResult failed, returning original:', err.message);
    return result;
  }
}

// ===== API ENDPOINTS =====

// POST /api/analyze
app.post('/api/analyze', aiLimiter, async (req, res) => {
  let { prompt, imageBase64, imageMimeType, symptoms, bodyArea, bodyHeatmapData, bodyRegions, lang } = req.body;

  // Total request body cap. Vercel rejects at the edge with plain-text
  // 413 FUNCTION_PAYLOAD_TOO_LARGE — but by then the user sees an
  // unfriendly "Internal server error". Catching the same limit here
  // gives a clean JSON error and matches the client's 4_000_000 preflight.
  const totalBody = (req.body && JSON.stringify(req.body).length) || 0;
  if (totalBody > 3_900_000) {
    return res.status(413).json({ error: 'Request is too large. Please remove the image or use a smaller photo.' });
  }

  // Input validation
  if (prompt && prompt.length > 5000) {
    return res.status(400).json({ error: 'Prompt too long (max 5000 characters)' });
  }
  if (symptoms && symptoms.length > 2000) {
    return res.status(400).json({ error: 'Symptoms description too long (max 2000 characters)' });
  }
  if (bodyArea && typeof bodyArea === 'string' && bodyArea.length > 1000) {
    return res.status(400).json({ error: 'Body area data too long' });
  }
  if (imageMimeType && !['image/jpeg', 'image/png', 'image/webp'].includes(imageMimeType)) {
    return res.status(400).json({ error: 'Unsupported image type' });
  }
  if (imageBase64 && imageBase64.length > 5 * 1024 * 1024) {
    return res.status(400).json({ error: 'Image too large (max 5MB)' });
  }

  // Check cache first (skip for images)
  if (!imageBase64 && symptoms) {
    const cacheKey = getCacheKey(symptoms, bodyArea, lang, bodyRegions);
    const cached = getCached(cacheKey);
    if (cached) {
      if (process.env.NODE_ENV !== 'production') {
        console.log('Cache hit for:', symptoms.slice(0, 30) + '...');
      }
      const normalizedCached = normalizeAIResponse({ ...cached, cached: true });
      const translatedCached = await translateResult(normalizedCached, lang);
      return res.json(translatedCached);
    }
  }

  const usedModels = [];
  let lastError = null;
  const sanitizeUsedModels = (arr) => process.env.NODE_ENV === 'production'
    ? arr.map(m => (m && m.model) ? m.model : String(m))
    : arr;

  // Test mode shortcut: skip real AI calls, return fast mock so the
  // rate-limit test doesn't burn quota waiting for 11 sequential calls.
  if (process.env.NODE_ENV === 'test') {
    const result = getMockDiagnosis(symptoms, bodyArea);
    const recommendedFacilities = recommendFacilities(result.severity, result.primaryCondition);
    const response = normalizeAIResponse({
      ...result,
      modelUsed: 'demo',
      modelsAttempted: sanitizeUsedModels(usedModels),
      responseTimeMs: 0,
      demoMode: true,
      recommendedFacilities
    });
    if (!imageBase64 && symptoms) {
      setCached(getCacheKey(symptoms, bodyArea, lang, bodyRegions), response);
    }
    const translated = await translateResult(response, lang);
    return res.json(translated);
  }

  // Image preprocessing: describe the photo, then let the text chain reason
  // over that description. Gemini 2.5 Flash, and exactly one call per upload
  // because the free tier allows 5 requests per minute.
  let imageDescription = '';
  if (imageBase64) {
    try {
      // Pass the patient's own words, not the server's JSON-schema prompt. The
      // vision model is asked to describe; a "reply with this JSON object" prompt
      // pushes it to guess a diagnosis instead.
      const visionRes = await describeImage(symptoms, imageBase64, imageMimeType);
      imageDescription = visionRes.description || '';
      usedModels.push({ model: 'gemini_vision', result: visionRes, error: null });
      console.log('Gemini vision description obtained (length: ' + imageDescription.length + ')');
    } catch (e) {
      console.error('Gemini vision failed:', e.message);
      usedModels.push({ model: 'gemini_vision', error: e.message });
    }
  }

  // Build aggregated prompt - handle case where prompt is undefined but symptoms provided
  // Strip any system-role / instruction prefix the frontend may have prepended so the
  // server's own system prompt is the authoritative one and there is no double-wrap.
  let rawPrompt = prompt || '';
  rawPrompt = rawPrompt.replace(/^You are\s+[^.\n]+[.\n]*/i, '').replace(/^Medical AI[^\n]*\n*/i, '').replace(/^I\'m an AI[^\n]*\n*/i, '').trim();
  let aggregatedPrompt = rawPrompt;
  if (symptoms && !aggregatedPrompt.includes('Patient description')) {
    aggregatedPrompt += (aggregatedPrompt ? '\n' : '') + 'Patient description: "' + symptoms + '"';
  }
  if (imageDescription) {
    aggregatedPrompt += '\n\nImage description: ' + imageDescription;
  }
  if (bodyArea) {
    aggregatedPrompt += '\nLocation: ' + bodyArea;
  }
  if (req.body.timePeriod) {
    aggregatedPrompt += '\nTime period: ' + req.body.timePeriod;
  }
  if (bodyHeatmapData && typeof bodyHeatmapData === 'object') {
    aggregatedPrompt += '\nHeatmap data: ' + JSON.stringify(bodyHeatmapData);
  }
  if (bodyRegions && Array.isArray(bodyRegions) && bodyRegions.length > 0) {
    aggregatedPrompt += '\nClicked body regions: ' + bodyRegions.join(', ');
  }

  // Ensure prompt has minimum content for AI models
  if (!aggregatedPrompt.trim() && symptoms) {
    aggregatedPrompt = 'Analyze these symptoms: ' + symptoms;
  }

  prompt = aggregatedPrompt;

  // Whether the chain has any text it can actually reason over. The vision
  // pre-pass folds the image into imageDescription, so an image-only upload DOES
  // carry signal and must not be skipped. Gating on the raw `symptoms` field here
  // is what used to send every photo-only analysis straight to demo mode.
  const hasTextSignal = Boolean(
    (symptoms && symptoms.trim()) ||
    imageDescription ||
    bodyArea ||
    (bodyRegions && Array.isArray(bodyRegions) && bodyRegions.length > 0) ||
    (bodyHeatmapData && typeof bodyHeatmapData === 'object')
  );

  // Do NOT nullify imageBase64. The image description is embedded above, but we
  // keep the raw data so image-capable models can also call their vision endpoints.

  // Text-only / symptom path
  for (const modelName of MODEL_PRIORITY) {
    if (modelName !== 'demo' && !isModelAvailable(modelName)) {
      if (process.env.NODE_ENV !== 'production') {
        console.log(modelName + ' rate limited, skipping...');
      }
      continue;
    }

    if (imageBase64 && MODEL_CAPABILITIES[modelName]?.supportsImages === false && !hasTextSignal) {
      if (process.env.NODE_ENV !== 'production') {
        console.log(modelName + ' does not support images and nothing describes it, skipping...');
      }
      continue;
    }

    try {
      let result;
      const startTime = Date.now();

      switch (modelName) {
        case 'nvidia':
          if (!process.env.NVIDIA_API_KEY) continue;
          result = await analyzeWithNvidia(prompt);
          incrementModel('nvidia');
          break;
        case 'groq':
          if (!process.env.GROQ_API_KEY) continue;
          result = await analyzeWithGroq(prompt);
          incrementModel('groq');
          break;
        case 'ollama':
          if (!ollamaAvailable) continue;
          result = await analyzeWithOllama(prompt);
          break;
        case 'demo':
          if (process.env.NODE_ENV !== 'production') {
            console.log('Using demo/mock diagnosis as fallback');
          }
          result = getMockDiagnosis(symptoms, bodyArea);
          break;
      }

      const duration = Date.now() - startTime;
      if (process.env.NODE_ENV !== 'production') {
        console.log('Used ' + modelName + ' (' + duration + 'ms)');
      }

      const recommendedFacilities = recommendFacilities(result.severity, result.primaryCondition);

      const response = normalizeAIResponse({
        ...result,
        modelUsed: modelName,
        modelsAttempted: sanitizeUsedModels(usedModels),
        responseTimeMs: duration,
        demoMode: modelName === 'demo',
        recommendedFacilities: recommendedFacilities
      });

      // Skip caching demo fallbacks so a brief AI outage doesn't poison the
      // cache with mock data for the next hour.
      if (!imageBase64 && symptoms && !response.demoMode) {
        setCached(getCacheKey(symptoms, bodyArea, lang, bodyRegions), response);
      }

      const translated = await translateResult(response, lang);
      return res.json(translated);

    } catch (error) {
      console.error(modelName + ' failed:', error.message);
      usedModels.push({ model: modelName, error: error.message });
      lastError = error;
      if (error.message && (error.message.includes('429') || error.message.includes('quota'))) {
        exhaustModel(modelName);
      }
      continue;
    }
  }

  // Final fallback
  if (process.env.NODE_ENV !== 'production') {
    console.log('All AI models failed, using demo mode as final fallback');
  }
  const demoResult = getMockDiagnosis(symptoms, bodyArea);
  const recommendedFacilities = recommendFacilities(demoResult.severity, demoResult.primaryCondition);
  const fallbackResponse = normalizeAIResponse({
    ...demoResult,
    modelUsed: 'demo',
    modelsAttempted: sanitizeUsedModels(usedModels),
    responseTimeMs: 0,
    demoMode: true,
    fallbackReason: 'All AI models unavailable, using demo data',
    recommendedFacilities: recommendedFacilities
  });
  const translatedFallback = await translateResult(fallbackResponse, lang);
  res.json(translatedFallback);
});

// POST /api/chat
const demoReplies = [
  "That is a great question. In general, this condition responds well to rest and proper self-care. However, everyone is different.",
  "Most people see improvement within 3-7 days. Monitor your symptoms and seek professional care if they worsen.",
  "Prevention is important. Good hygiene, adequate sleep, and staying hydrated are your best defenses.",
  "Common triggers include stress, certain foods, and environmental factors. Keeping a symptom journal can help identify patterns.",
  "While this is usually manageable at home, do not hesitate to consult a healthcare provider if you are concerned."
];

app.post('/api/chat', aiLimiter, verifyToken, requireVerifiedEmail, async (req, res) => {
  const { prompt } = req.body;
  const lang = (req.body && req.body.lang) ? req.body.lang : 'en';

  // Build the response through a single path so the reply can be translated
  // before being sent (chat is silent for non-English users otherwise).
  let reply = null;
  let modelUsed = null;

  // Groq is now the primary model for chat (Gemini removed)
  if (reply === null && process.env.GROQ_API_KEY && isModelAvailable('groq')) {
    try {
      const response = await groq.chat.completions.create({
        model: GROQ_MODEL,
        temperature: 0.7,
        // Reasoning models spend tokens thinking before they write the reply, so
        // a small budget here yields empty content. Treat empty as a failure so
        // the chain falls through instead of returning a blank chat bubble.
        max_tokens: 2048,
        messages: [
          { role: 'system', content: 'You are a helpful medical AI assistant. Be concise and encouraging.' },
          { role: 'user', content: prompt }
        ]
      });
      const chatText = (response.choices[0].message.content || '').trim();
      if (!chatText) throw new Error('Groq chat returned empty content');
      incrementModel('groq');
      reply = chatText;
      modelUsed = 'groq';
    } catch (error) {
      console.log('Groq chat failed:', error.message);
      if (error.message && (error.message.includes('429') || error.message.includes('quota'))) exhaustModel('groq');
    }
  }

  if (reply === null && ollamaAvailable) {
    try {
      reply = await chatWithOllama(prompt);
      modelUsed = 'ollama';
    } catch (error) {
      console.log('Ollama chat failed:', error.message);
    }
  }

  if (reply === null) {
    reply = demoReplies[Math.floor(Math.random() * demoReplies.length)];
    modelUsed = 'demo';
  }

  // Translate the reply to the user's language (no-op for 'en').
  // Falls back to the original English string if translation fails.
  const translatedReply = await translateText(reply, lang);
  res.json({ reply: translatedReply, modelUsed });
});

// GET /api/health-news
app.get('/api/health-news', async (req, res) => {
  try {
    // Step 1: Check database for fresh cached news (less than 1 hour old)
    if (await newsDAO.hasFreshNews(60)) {
      const dbNews = await newsDAO.getNews(20);
      if (dbNews.length > 0) {
        return res.json({ news: dbNews, cached: true, source: 'database' });
      }
    }

    let news = [];

    const newsPrompt = `You are a health news curator for Ethiopia. Generate as many recent health news items as are relevant to Ethiopian healthcare.

For each news item, provide:
1. icon (emoji representing the topic)
2. tag (alert, info, warning, or news)
3. tagName (Alert, Update, Advisory, or News)
4. date (current date in format: May 5, 2026)
5. title (short, attention-grabbing headline)
6. body (2-3 sentences explaining the health issue and its relevance to Ethiopia)

Topics to cover:
- Disease outbreaks (malaria, dengue, cholera, etc.)
- Vaccination campaigns
- Seasonal health advisories
- New healthcare facilities or services
- Public health initiatives

Return ONLY valid JSON in this exact format:
[
  {
    "icon": "🦠",
    "tag": "alert",
    "tagName": "Alert",
    "date": "May 5, 2026",
    "title": "Malaria Prevention Alert",
    "body": "Increased malaria cases reported..."
  }
]`;

    // Groq goes first. It returns this array in a few seconds, while NVIDIA's
    // gpt-oss-20b needed about 53s for the same array, which exceeds the Vercel
    // maxDuration before the result can be saved. Both providers share one
    // deadline so a slow one cannot overrun the request.
    const newsAbort = new AbortController();
    const newsTimer = setTimeout(() => newsAbort.abort(), NEWS_AI_TIMEOUT_MS);

    if ((!news || news.length === 0) && groq && isModelAvailable('groq')) {
      try {
        const groqResponse = await groq.chat.completions.create({
          model: GROQ_NEWS_MODEL,
          temperature: 0.7,
          max_tokens: NEWS_MAX_TOKENS,
          messages: [
            { role: 'system', content: 'You are a health news curator. Respond ONLY with valid JSON array. No markdown, no explanations.' },
            { role: 'user', content: newsPrompt }
          ]
        }, { signal: newsAbort.signal });
        const groqText = groqResponse.choices[0].message.content || '';
        let groqExtracted = [];
        const startG = groqText.indexOf('[');
        const endG = groqText.lastIndexOf(']');
        let groqPortion = groqText;
        if (startG !== -1 && endG !== -1 && endG > startG) {
          groqPortion = groqText.slice(startG, endG + 1);
        }
        try {
          groqExtracted = extractJSON(groqPortion);
        } catch (_) {
          const matches = groqPortion.match(/\{[^}]*\}/g) || [];
          groqExtracted = matches.map(str => {
            try { return JSON.parse(str); } catch (e) { return null; }
          }).filter(Boolean);
        }
        const groqValid = Array.isArray(groqExtracted) && groqExtracted.length > 0 && groqExtracted.every(item =>
          item && typeof item.icon === 'string' && typeof item.tag === 'string' && typeof item.tagName === 'string' && typeof item.date === 'string' && item.title && (typeof item.body === 'string')
        );
        if (groqValid) {
          news = groqExtracted;
          incrementModel('groq');
        } else {
          console.log('Groq extraction yielded invalid structure, falling back');
          news = [];
        }
      } catch (e) {
        if (newsAbort.signal.aborted) {
          console.log('Groq news generation timed out after ' + NEWS_AI_TIMEOUT_MS + 'ms');
        } else {
          console.log('Groq news generation failed:', e.message);
        }
      }
    }

    if ((!news || news.length === 0) && nvidia && isModelAvailable('nvidia')) {
      try {
        const response = await nvidia.chat.completions.create({
          model: NVIDIA_MODEL,
          temperature: 0.7,
          max_tokens: NEWS_MAX_TOKENS,
          messages: [
            { role: 'system', content: 'You are a health news curator. Respond ONLY with valid JSON array. No markdown, no explanations.' },
            { role: 'user', content: newsPrompt }
          ]
        }, { signal: newsAbort.signal });

        // Reasoning models return null content when the token budget runs out.
        const responseText = response.choices[0].message.content || '';
        const objMatches = responseText.match(/\{[^}]*\}/g) || [];
        const extracted = objMatches.map(str => {
          try { return JSON.parse(str); } catch (e) { return null; }
        }).filter(Boolean);
        const isValid = Array.isArray(extracted) && extracted.length > 0 && extracted.every(item =>
          item && typeof item.icon === 'string' && typeof item.tag === 'string' && typeof item.tagName === 'string' && typeof item.date === 'string' && item.title && (typeof item.body === 'string')
        );
        if (isValid) {
          news = extracted;
          incrementModel('nvidia');
        } else {
          console.log('NVIDIA extraction yielded invalid structure, falling back');
          news = [];
        }
      } catch (error) {
        if (newsAbort.signal.aborted) {
          console.log('NVIDIA news generation timed out after ' + NEWS_AI_TIMEOUT_MS + 'ms');
        } else {
          console.log('NVIDIA news generation failed:', error.message);
          exhaustModel('nvidia');
        }
      }
    }
    clearTimeout(newsTimer);

    if (!news || news.length === 0) {
      news = [
        {
          icon: '🦠',
          tag: 'alert',
          tagName: 'Alert',
          date: new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }),
          title: 'Malaria Prevention Alert',
          body: 'Increased malaria cases reported in Amhara region. Use mosquito nets and seek early treatment for fever symptoms. Prevention is key during the rainy season.'
        },
        {
          icon: '💉',
          tag: 'info',
          tagName: 'Update',
          date: new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }),
          title: 'Vaccination Campaign Update',
          body: 'Free vaccination clinics available at Gondar University Hospital for children under 5 years. Protect your family against preventable diseases.'
        },
        {
          icon: '🌡️',
          tag: 'warning',
          tagName: 'Advisory',
          date: new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }),
          title: 'Seasonal Flu Advisory',
          body: 'Flu season approaching. Practice good hygiene, wash hands frequently, and consider getting vaccinated if at high risk for complications.'
        },
        {
          icon: '🏥',
          tag: 'info',
          tagName: 'News',
          date: new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }),
          title: 'New Health Center Opening',
          body: 'A new health center opening in Azezo next week, expanding healthcare access for the community. More services available closer to home.'
        }
      ];
    }

    // Step 2: Persist fresh news to database
    await newsDAO.saveNews(news);
    // Step 3: Also cache in memory for the remaining TTL window
    setCached('health_news', news);

    const dbSource = nvidia && isModelAvailable('nvidia') ? 'nvidia'
      : groq && isModelAvailable('groq') ? 'groq'
      : 'static';
    res.json({ news, cached: false, source: dbSource });
  } catch (error) {
    console.error('Health news error:', error);
    res.status(500).json({ error: 'Failed to fetch health news' });
  }
});

// GET /api/health
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.1.0'
  });
});

// GET /api/status
app.get('/api/status', (req, res) => {
  res.json({
    models: {
      groq: {
        available: isModelAvailable('groq'),
        usedToday: rateLimits.groq,
        dailyLimit: DAILY_LIMITS.groq,
        hasKey: !!process.env.GROQ_API_KEY,
        supportsImages: false
      },
      nvidia: {
        available: isModelAvailable('nvidia'),
        usedToday: rateLimits.nvidia,
        dailyLimit: DAILY_LIMITS.nvidia,
        hasKey: !!process.env.NVIDIA_API_KEY,
        supportsImages: false
      },
      ollama: {
        available: ollamaAvailable,
        usedToday: 0,
        dailyLimit: 'unlimited',
        hasKey: ollamaAvailable,
        supportsImages: false
      },
      gemini: {
        // Image analysis only. Not part of MODEL_PRIORITY, so it has no daily
        // counter here; the free tier is 5 requests per minute.
        available: !!process.env.GEMINI_API_KEY,
        usedToday: 0,
        dailyLimit: 'free tier: 5/min',
        hasKey: !!process.env.GEMINI_API_KEY,
        supportsImages: true
      }
    },
    rateLimitResetsAt: new Date(rateLimits.resetTime).toISOString(),
    demoMode: !ollamaAvailable && !process.env.GROQ_API_KEY && !process.env.NVIDIA_API_KEY
  });
});

// Root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'IIndex.html'));
});

  // Export and listen
  if (process.env.NODE_ENV !== 'test') {
    // ===== Startup Validation =====
    const missingVars = [];

    if (!process.env.SUPABASE_URL) {
      missingVars.push('SUPABASE_URL');
    }
    if (!process.env.SUPABASE_SERVICE_KEY) {
      missingVars.push('SUPABASE_SERVICE_KEY');
    }
    if (!process.env.DATA_ENC_KEY) {
      missingVars.push('DATA_ENC_KEY');
    }
    if (!process.env.GEMINI_API_KEY && !process.env.GROQ_API_KEY && !process.env.NVIDIA_API_KEY) {
      missingVars.push('GEMINI_API_KEY or GROQ_API_KEY or NVIDIA_API_KEY (at least one required)');
    }

    if (missingVars.length > 0) {
      console.error('');
      console.error('========================================');
      console.error('Missing required environment variables:');
      missingVars.forEach(v => console.error('  - ' + v));
      console.error('========================================');
      console.error('');
      throw new Error('Missing required environment variables: ' + missingVars.join(', '));
    }

    // Schedule news cleanup on startup (delete news older than 7 days)
    newsDAO.deleteOldNews(7).then(deleted => {
      if (deleted > 0) console.log('Cleaned up ' + deleted + ' old news items from database');
    }).catch(err => {
      console.log('News cleanup skipped:', err.message);
    });

    console.log('');
    console.log('CORS allowed origins:', allowedOrigins.join(', '));
    console.log('');

    app.listen(process.env.PORT || 3000, () => {
    console.log('');
    console.log('🚀 MediScan Multi-Model Server running on http://localhost:' + (process.env.PORT || 3000));
    console.log('📊 Model priority:', MODEL_PRIORITY.join(' → '));
    console.log('');
    console.log('API Keys configured:');
    console.log('  Groq:', process.env.GROQ_API_KEY ? 'yes' : 'no');
    console.log('  NVIDIA text:', process.env.NVIDIA_API_KEY ? 'yes' : 'no');
    console.log('  Gemini vision (images):', process.env.GEMINI_API_KEY ? 'yes' : 'no');
    console.log('');
    const rateWindow = process.env.RATE_LIMIT_WINDOW ? parseInt(process.env.RATE_LIMIT_WINDOW) : 1;
    const rateMax = process.env.RATE_LIMIT_MAX ? parseInt(process.env.RATE_LIMIT_MAX) : 20;
    console.log('Rate limits: ' + rateMax + ' requests per ' + rateWindow + ' minute(s)');
    });
  }

  // Global error handler catches unhandled promise rejections and returns
  // clean JSON instead of raw stack traces or unhelpful 500s.
  app.use((err, req, res, next) => {
    const requestId = require('crypto').randomBytes(4).toString('hex');
    const status = err.status || 500;
    if (process.env.NODE_ENV === 'production') {
      // PHI may sit in req.body / err.stack; scrub both in prod logs.
      console.error('Unhandled error:', { requestId, status, code: err.code, message: err.message });
      res.status(status).json({ error: 'Internal server error', requestId });
    } else {
      console.error('Unhandled error:', err);
      res.status(status).json({ error: err.message, requestId });
    }
  });

  app.__normalizeAIResponse = normalizeAIResponse;
  app.__extractJSON = extractJSON;
  // Exposed so tests can read the live model IDs and timeout budgets instead of
  // restating them. They are locals of this factory, not module scope.
  app.__modelConfig = {
    MODEL_PRIORITY,
    GROQ_MODEL,
    NVIDIA_MODEL,
    GROQ_NEWS_MODEL,
    GROQ_TIMEOUT_MS,
    NVIDIA_TIMEOUT_MS
  };
  return app;
}

const app = createApp();
module.exports = app;
module.exports.createApp = createApp;
module.exports.normalizeAIResponse = app.__normalizeAIResponse;
module.exports.extractJSON = app.__extractJSON;
// The model config is declared inside createApp(), so it reaches the outside
// world on `app`, like the two helpers above. Tests read these rather than
// restating the values and drifting: see tests/ai-model-config.test.js.
module.exports.modelConfig = app.__modelConfig;