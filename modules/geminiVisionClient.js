/**
 * Describes an image so the text chain can reason over its contents.
 *
 * This replaced modules/nvidiaVisionClient.js, which called
 * nvidia/nemotron-nano-12b-v2-vl (NVIDIA end-of-life, HTTP 410) and then
 * meta/llama-3.2-11b-vision-instruct. The NVIDIA endpoint was the problem, not
 * the model name: the same 50KB photo came back in 5.7s, 72s and 85s across
 * runs, with a 60s stall on the 90b variant. That variance cannot live inside a
 * request budget, so image analysis moved to Gemini.
 *
 * gemini-2.5-flash was measured on 2026-10-18 across four runs on a real photo:
 * 2.6s, 3.3s, 3.6s, 3.9s, each with a correct description.
 *
 * Two Gemini-specific details:
 *   - thinkingBudget 0. Thinking costs latency and can consume the entire
 *     output budget, leaving the text parts empty. Off, the answer lands
 *     directly in the text parts.
 *   - The key is free tier at 5 requests per minute, so one call per image is
 *     the budget. A 429 surfaces as a clear error and the caller degrades.
 *
 * Plain fetch rather than a vendor SDK keeps this dependency-free, matching the
 * Ollama and MyMemory calls elsewhere in the project.
 */
const GEMINI_VISION_MODEL = 'gemini-2.5-flash';
const VISION_TIMEOUT_MS = 12000;

const DESCRIPTION_INSTRUCTION = [
  'Describe the visible features of the attached image in 2 to 3 sentences.',
  'Note what a clinician would observe: colour, texture, shape, edges, size, and any asymmetry.',
  'Do not name a diagnosis. Do not give medical advice.',
  'Answer in plain prose, not JSON.'
].join(' ');

async function describeImage(patientWords, imageBase64, imageMimeType) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('GEMINI_API_KEY not set');
  }

  const parts = [{ text: DESCRIPTION_INSTRUCTION }];
  // `patientWords` is the patient's own description, not the server's JSON
  // schema prompt. Asking a describe-the-image model to "reply with this JSON
  // object" pushes it to invent a diagnosis instead of describing.
  if (patientWords && String(patientWords).trim()) {
    parts.push({ text: 'The patient described it as: ' + String(patientWords).trim() });
  }
  if (imageBase64) {
    parts.push({
      inline_data: {
        mime_type: imageMimeType || 'image/jpeg',
        data: imageBase64,
      },
    });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), VISION_TIMEOUT_MS);

  let body;
  let status;
  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_VISION_MODEL}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey,
        },
        body: JSON.stringify({
          contents: [{ parts }],
          generationConfig: {
            thinkingConfig: { thinkingBudget: 0 },
            maxOutputTokens: 512,
            temperature: 0.2,
          },
        }),
        signal: controller.signal,
      }
    );
    status = response.status;
    body = await response.json();
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error('Gemini vision timeout after ' + VISION_TIMEOUT_MS + 'ms');
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }

  if (status !== 200 || !body || body.error) {
    const detail = (body && body.error && body.error.message) || 'unknown error';
    // First line only. A 429 here is the free-tier per-minute cap, and saying so
    // beats a generic failure in the logs.
    throw new Error(`Gemini vision failed (${status}): ` + String(detail).split('\n')[0]);
  }

  const candidate = (body.candidates || [])[0] || {};
  const outParts = (candidate.content && candidate.content.parts) || [];
  const text = outParts
    .filter((p) => !p.thought)
    .map((p) => p.text || '')
    .join('')
    .trim();

  if (!text) {
    throw new Error('Gemini vision returned an empty description (' + (candidate.finishReason || 'no candidates') + ')');
  }
  return { description: text };
}

module.exports = { describeImage, GEMINI_VISION_MODEL, VISION_TIMEOUT_MS };