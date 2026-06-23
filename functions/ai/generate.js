// Revise — AI card generation via Gemini
// Env vars required: GEMINI_API_KEY, REVISE_KV

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });

  // Require a valid session
  const token = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)rv_sess=([^;]+)/)?.[1];
  if (!token) return json({ error: 'Not signed in.' }, 401);
  const sess = token ? JSON.parse(await env.REVISE_KV.get(`session:${token}`) || 'null') : null;
  if (!sess) return json({ error: 'Not signed in.' }, 401);

  const { subject, subjectName, masteryPercent = 0, existingQuestions = [], count = 4 } = await request.json().catch(() => ({}));
  if (!subject || !subjectName) return json({ error: 'Missing subject.' }, 400);
  if (!env.GEMINI_API_KEY) return json({ error: 'AI not configured.' }, 500);

  const level = masteryPercent < 30 ? 'beginner' : masteryPercent < 70 ? 'intermediate' : 'advanced';
  const existing = existingQuestions.slice(0, 20).join('\n');

  const prompt = `You are a flashcard generator for a ${subjectName} revision app.
The student is at ${level} level (${masteryPercent}% mastery).
Generate exactly ${count} NEW flashcard question-and-answer pairs for ${subjectName}.
${existing ? `Do NOT repeat any of these existing questions:\n${existing}\n` : ''}
Rules:
- Questions should be clear and concise
- Answers should be short (1–2 sentences or a formula/fact)
- Difficulty should match ${level} level
- Return ONLY a JSON array, no markdown, no explanation

Format:
[{"q":"question here","a":"answer here"},...]`;

  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${env.GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 1024 },
      }),
    }
  );

  if (!res.ok) {
    const e = await res.text();
    console.error('[ai/generate] Gemini error:', e);
    return json({ error: 'AI request failed. Check your API key.' }, 502);
  }

  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';

  // Strip markdown code fences if present
  const clean = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();

  let cards;
  try {
    cards = JSON.parse(clean);
    if (!Array.isArray(cards)) throw new Error('Not an array');
    cards = cards.filter(c => c.q && c.a).slice(0, count);
  } catch {
    console.error('[ai/generate] Bad JSON from Gemini:', clean);
    return json({ error: 'AI returned unexpected format. Try again.' }, 502);
  }

  return json({ cards });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
