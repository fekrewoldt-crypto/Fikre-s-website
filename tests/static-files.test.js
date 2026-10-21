// Tests for the static-file routes added in Server-v2.js. These exist
// because Vercel's serverless runtime doesn't bundle the project root
// into the function, so express.static alone returns 404 for every
// image, module, locale, or CSS file the app needs.

const request = require('supertest');
const fs = require('fs');
const path = require('path');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.DATA_ENC_KEY = 'a'.repeat(64);
process.env.RATE_LIMIT_WINDOW = '1';
process.env.RATE_LIMIT_MAX = '1000';

const { createApp } = require('../Server-v2');

describe('Static file routes (Vercel serverless support)', () => {
  const app = createApp();

  describe('whitelisted PNG / CSS / JS assets', () => {
    const cases = [
      { path: '/male-front.png',        contentType: 'image/png' },
      { path: '/male-back.png',         contentType: 'image/png' },
      { path: '/female-front.png',      contentType: 'image/png' },
      { path: '/female-back.png',       contentType: 'image/png' },
      { path: '/reference-male.png',    contentType: 'image/png' },
      { path: '/hospital-map.css',      contentType: 'text/css' },
      { path: '/hospital-map.js',       contentType: 'application/javascript' },
      { path: '/timeline.js',           contentType: 'application/javascript' }
    ];

    test.each(cases)('GET $path returns 200 with $contentType', async ({ path: p, contentType }) => {
      const res = await request(app).get(p);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(new RegExp(contentType.replace(/[.+*?^${}()|[\]\\]/g, '\\$&'), 'i'));
    });
  });

  describe('whitelisted /modules/*.js', () => {
    const modules = [
      'body-heatmap.js',
      'body-heatmap-muscles.js',
      'heatmap-switcher.js',
      'heatmap-state.js',
      'demo-body-heatmap-simple.js',
      'translations.js'
    ];

    test.each(modules)('GET /modules/%s returns 200 with JS content-type', async (file) => {
      const res = await request(app).get('/modules/' + file);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/javascript/i);
    });
  });

  describe('whitelisted /locales/*.json', () => {
    test('GET /locales/am.json returns 200 with JSON content-type', async () => {
      const res = await request(app).get('/locales/am.json');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/json/i);
    });
  });

  describe('unknown / non-whitelisted files are rejected', () => {
    const unknown = [
      '/modules/secret.js',
      '/modules/heatmap-state.js.bak',
      '/locales/en.json',
      '/locales/zz.json',
      '/random.png',
      '/malware.css'
    ];

    test.each(unknown)('GET %s returns 404', async (p) => {
      const res = await request(app).get(p);
      expect(res.status).toBe(404);
    });
  });

  describe('path-traversal protection', () => {
    // These would let a malicious client read source code or env files
    // if the static handler didn't normalize / sandbox file paths.
    const traversal = [
      '/modules/../Server-v2.js',
      '/modules/../package.json',
      '/modules/.env',
      '/locales/../Server-v2.js',
      '/locales/.env',
      '/modules/heatmap-state.js/../Server-v2.js'
    ];

    test.each(traversal)('GET %s does not leak project files', async (p) => {
      const res = await request(app).get(p);
      // Must reject with 400 (path traversal) or 404 (not found) — never 200
      // with file content from outside the module whitelist.
      expect([400, 404]).toContain(res.status);
      if (res.status === 200) {
        const body = typeof res.text === 'string' ? res.text : '';
        // Must not contain env-style secrets
        expect(body).not.toMatch(/SUPABASE_SERVICE_KEY|GEMINI_API_KEY|GROQ_API_KEY/i);
        // Must not be raw server source
        expect(body).not.toMatch(/require\(['"]dotenv['"]\)/);
      }
    });

    test('dotfiles at the project root are not served (e.g. /.env)', async () => {
      // Only run this if a .env actually exists locally so we're testing
      // the protection, not just absence.
      const envPath = path.join(__dirname, '..', '.env');
      if (!fs.existsSync(envPath)) return;
      const res = await request(app).get('/.env');
      expect(res.status).toBe(404);
    });
  });

  describe('API routes still work alongside static handler', () => {
    test('GET /api/status returns 200', async () => {
      const res = await request(app).get('/api/status');
      expect(res.status).toBe(200);
    });
  });
});
