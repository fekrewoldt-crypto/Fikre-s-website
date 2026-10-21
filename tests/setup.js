// Jest test setup for MediScan auth system
// Set environment variables BEFORE any application code loads

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key-for-mediscan-auth-tests-only-do-not-use-in-prod';
process.env.DATA_ENC_KEY = 'a'.repeat(64); // 64 hex chars = 32 bytes for AES-256
process.env.BCRYPT_ROUNDS = '4'; // Faster hashing for tests
process.env.RATE_LIMIT_WINDOW = '1'; // 1 minute
process.env.RATE_LIMIT_MAX = '10'; // Lower for faster rate-limit tests

// Keep the image path off unless a test opts in. Server-v2.js calls
// dotenv.config(), which would otherwise load the real GEMINI_API_KEY from .env
// and any test posting an image would make a live vision call against the
// free-tier quota. dotenv does not overwrite an existing value, so an empty
// string here is enough to hold it off.
process.env.GEMINI_API_KEY = '';

// Point Ollama at a closed port so it always reports unavailable. Otherwise the
// suite behaves differently depending on whether the developer happens to have
// Ollama running: with it up, the chain ends at Ollama and the tests that assert
// a demo fallback fail. Port 9 is the discard port, so the probe is refused
// immediately. Tests that need the real chain read it as unavailable, which is
// also what production on Vercel sees.
process.env.OLLAMA_URL = 'http://127.0.0.1:9';

// Export encryption constants for use in tests
const crypto = require('crypto');
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

module.exports = {
  IV_LENGTH,
  TAG_LENGTH,
  ALGORITHM,
  TEST_ENC_KEY: process.env.DATA_ENC_KEY,
};