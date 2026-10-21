// P2 hygiene fixes:
//   1. modelsAttempted leaks provider error text in production
//   2. Missing Vary: Origin on CORS responses
//   3. Global error handler dumps full stack + req body to logs in production

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key-server-hygiene-suite-only';
process.env.DATA_ENC_KEY = 'a'.repeat(64);
process.env.RATE_LIMIT_WINDOW = '1';
process.env.RATE_LIMIT_MAX = '10000';
process.env.AI_RATE_LIMIT_MAX = '10000';
process.env.GROQ_API_KEY = 'test-groq-key';
process.env.NVIDIA_API_KEY = 'test-nvidia-key';
process.env.VISION_API_KEY = '';

jest.mock('openai', () => {
  class MockOpenAI {
    constructor() {
      this.chat = {
        completions: {
          create: async () => {
            const err = new Error('upstream provider failure secret-key-leak');
            err.status = 500;
            throw err;
          }
        }
      };
    }
  }
  return { OpenAI: MockOpenAI };
});

require('./setup');
const request = require('supertest');
const { createApp } = require('../Server-v2.js');

const withEnv = async (env, fn) => {
  const prev = process.env.NODE_ENV;
  process.env.NODE_ENV = env;
  try { return await fn(); }
  finally { process.env.NODE_ENV = prev; }
};

describe('Fix 1: modelsAttempted sanitization', () => {
  it('strips provider error strings in production', async () => {
    const app = createApp();
    const res = await withEnv('production', () =>
      request(app).post('/api/analyze').send({ symptoms: 'prod hygiene ' + Date.now() })
    );
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.modelsAttempted)).toBe(true);
    const entries = res.body.modelsAttempted;
    expect(entries.length).toBeGreaterThan(0);
    for (const m of entries) {
      expect(typeof m).toBe('string');
      expect(m).not.toMatch(/:/);
      expect(m).not.toMatch(/upstream|provider|failure|secret|leak/i);
    }
    const set = new Set(entries);
    const hasProvider = set.has('groq') || set.has('nvidia') || set.has('gemini_vision');
    expect(hasProvider).toBe(true);
  });

  it('keeps error context in non-production for debugging', async () => {
    const app = createApp();
    const res = await withEnv('development', () =>
      request(app).post('/api/analyze').send({ symptoms: 'dev hygiene ' + Date.now() })
    );
    expect(res.status).toBe(200);
    const entries = res.body.modelsAttempted;
    expect(Array.isArray(entries)).toBe(true);
    expect(entries.length).toBeGreaterThan(0);
    const withError = entries.find(m => m && typeof m === 'object' && m.error);
    expect(withError).toBeTruthy();
    expect(typeof withError.error).toBe('string');
  });
});

describe('Fix 2: Vary: Origin on CORS responses', () => {
  it('sets Vary header containing Origin', async () => {
    const app = createApp();
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    const vary = res.headers.vary || '';
    expect(vary.toLowerCase()).toContain('origin');
  });
});

describe('Fix 3: error handler scrubs stack + adds requestId', () => {
  it('production response has requestId and no stack trace', async () => {
    const app = createApp();
    const stack = app._router.stack;
    // Insert a throwing route just before the global error handler so
    // Express's error-lookup walks forward into the handler.
    const errorHandlerIdx = stack.findIndex(l => l.handle && l.handle.length === 4);
    expect(errorHandlerIdx).toBeGreaterThan(-1);
    app.get('/__hygiene_boom', (req, res, next) => {
      const err = new Error('symptom text fever 39C patient PHI');
      err.status = 500;
      next(err);
    });
    const boomLayer = stack.pop();
    stack.splice(errorHandlerIdx, 0, boomLayer);

    const origError = console.error;
    const logs = [];
    console.error = (...args) => logs.push(args);
    try {
      const res = await withEnv('production', () =>
        request(app).get('/__hygiene_boom')
      );
      expect(res.status).toBe(500);
      expect(res.body).toHaveProperty('requestId');
      expect(typeof res.body.requestId).toBe('string');
      expect(res.body.requestId.length).toBeGreaterThan(0);
      expect(res.body).not.toHaveProperty('stack');
      const bodyStr = JSON.stringify(res.body);
      expect(bodyStr).not.toMatch(/at .*Server-v2/);
      expect(bodyStr).not.toContain('symptom text fever');
      const logged = JSON.stringify(logs);
      expect(logged).not.toMatch(/at .*Server-v2\.js:\d+/);
    } finally {
      console.error = origError;
    }
  });
});
