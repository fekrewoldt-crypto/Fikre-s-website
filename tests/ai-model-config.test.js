// Guards the AI model configuration.
//
// Every model this project was pointed at got retired upstream during 2026:
// Groq's llama-3.3-70b-versatile (model_not_found) and gemma-7b-it
// (model_decommissioned), NVIDIA's openai/gpt-oss-120b and
// nvidia/nemotron-nano-12b-v2-vl (both HTTP 410), and gemini-2.5-flash-lite
// ("no longer available to new users"). None of it threw a visible error. The
// fallback chain walked past each dead model and served demo data, so the
// regression was invisible to every other test in this suite.
//
// These tests fail loudly instead: if a retired ID comes back, or if the
// per-provider timeouts stop fitting under the Vercel function limit, this
// suite goes red rather than production going quiet.
const fs = require('fs');
const path = require('path');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

// Model IDs confirmed retired, end-of-life, or not accessible on this account.
const RETIRED_MODEL_IDS = [
  'llama-3.3-70b-versatile',
  'gemma-7b-it',
  'nvidia/nemotron-nano-12b-v2-vl',
  'gemini-2.5-flash-lite',
  'gpt-4o-mini',
];

// Server-side image client, require()d by Server-v2.js. Not a browser script.
const VISION_CLIENT = 'modules/geminiVisionClient.js';

describe('AI model configuration', () => {
  let serverSrc;
  let vercelConfig;
  let vision;

  beforeAll(() => {
    serverSrc = read('Server-v2.js');
    vercelConfig = JSON.parse(read('vercel.json'));
    vision = require('../' + VISION_CLIENT);
  });

  const serverConst = (name) => {
    const match = serverSrc.match(new RegExp(`const ${name} = (\\d+|'[^']+')`));
    return match ? match[1].replace(/'/g, '') : null;
  };

  describe('model IDs point at models that still exist', () => {
    it('Groq text analysis uses a live model', () => {
      expect(serverConst('GROQ_MODEL')).toBe('openai/gpt-oss-120b');
    });

    it('Groq news fallback uses a live model', () => {
      expect(serverConst('GROQ_NEWS_MODEL')).toBe('openai/gpt-oss-20b');
    });

    it('NVIDIA text fallback uses a live model', () => {
      // openai/gpt-oss-120b is Groq's live model but is retired ON NVIDIA.
      // The provider matters as much as the ID here.
      expect(serverConst('NVIDIA_MODEL')).toBe('openai/gpt-oss-20b');
    });

    it('vision uses a live model', () => {
      expect(vision.GEMINI_VISION_MODEL).toBe('gemini-2.5-flash');
    });
  });

  describe('retired model IDs do not creep back in', () => {
    it.each(RETIRED_MODEL_IDS)('%s is not configured anywhere', (id) => {
      // Only quoted occurrences count, so the comments that name these dead IDs
      // stay allowed.
      expect(serverSrc).not.toContain(`'${id}'`);
      expect(read(VISION_CLIENT)).not.toContain(`'${id}'`);
    });

    it('does not reuse the Groq model ID on NVIDIA', () => {
      const occurrences = serverSrc.split(`'openai/gpt-oss-120b'`).length - 1;
      expect(occurrences).toBe(1);
    });
  });

  describe('the fallback chain is wired in order', () => {
    it('declares groq before nvidia before demo', () => {
      const match = serverSrc.match(/const MODEL_PRIORITY = \[([^\]]+)\]/);
      expect(match).not.toBeNull();
      const order = match[1].split(',').map((s) => s.trim().replace(/'/g, ''));
      expect(order).toEqual(['groq', 'nvidia', 'ollama', 'demo']);
    });

    it('every model call site uses a named constant, not a literal', () => {
      // A hardcoded ID in a call site is how the last set of dead models went
      // unnoticed. These two are not provider models: llama3.2 is Ollama's local
      // model name, and gemini_vision is a label in the modelsAttempted list.
      const allowedLiterals = ['llama3.2', 'gemini_vision'];
      const literals = (serverSrc.match(/model: '[^']+'/g) || [])
        .filter((entry) => !allowedLiterals.some((ok) => entry.includes(`'${ok}'`)));
      expect(literals).toEqual([]);
    });
  });

  describe('the timeout budget fits inside the Vercel function limit', () => {
    const maxDurationMs = () =>
      (vercelConfig.builds[0].config.maxDuration || 10) * 1000;

    it('gives the function more than the old 10s ceiling', () => {
      // At 10s the function was edge-killed before a slow provider could even
      // time out, so the chain could never reach demo mode cleanly.
      expect(maxDurationMs()).toBeGreaterThan(10000);
    });

    it('worst-case provider timeouts sum to less than maxDuration', () => {
      const groq = Number(serverConst('GROQ_TIMEOUT_MS'));
      const nvidia = Number(serverConst('NVIDIA_TIMEOUT_MS'));
      const visionTimeout = vision.VISION_TIMEOUT_MS;

      expect(groq).toBeGreaterThan(0);
      expect(nvidia).toBeGreaterThan(0);
      expect(visionTimeout).toBeGreaterThan(0);

      // Worst case: vision describes the image, then each text provider burns its
      // whole budget before the chain falls through to demo mode.
      const worstCase = groq + nvidia + visionTimeout;
      expect(worstCase).toBeLessThan(maxDurationMs());
    });
  });

  describe('the image-only path reaches the text chain', () => {
    it('gate keys off usable signal rather than the raw symptoms field', () => {
      // The old gate skipped every text model for a photo with no typed
      // symptoms, even when the vision model had already described the image.
      // Photo-only analyses silently returned demo data.
      expect(serverSrc).toContain('const hasTextSignal');
      expect(serverSrc).toMatch(/!hasTextSignal/);
    });

    it('the vision description counts as signal', () => {
      const block = serverSrc.match(/const hasTextSignal = Boolean\(([\s\S]*?)\);/);
      expect(block).not.toBeNull();
      expect(block[1]).toContain('imageDescription');
    });

    it('keeps the server-only vision client off the public static whitelist', () => {
      // The client lives in modules/ beside browser scripts but is require()d by
      // the server. On Vercel the whitelist is the only thing that can serve a
      // module, so leaving it out is what keeps the source off the deployed site.
      expect(serverSrc).not.toContain("'/modules/geminiVisionClient.js'");
    });
  });
});