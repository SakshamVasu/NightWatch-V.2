/**
 * Optional AI chat — bring-your-own-key. Three providers, direct browser fetch,
 * no backend. Grounded with buildScanContext() so answers are about the scan.
 *
 * PRIVACY: using this mode sends the scan context (and the conversation) to the
 * chosen provider. The UI makes this explicit; the default mode is fully local.
 *
 * NOTE: browser-origin calls to these APIs can be blocked by CORS depending on
 * provider/policy. Errors are surfaced to the user with guidance.
 */
import type { ParsedScan } from './types';
import { buildScanContext, type ChatMsg } from './localAssistant';

export type Provider = 'openai' | 'anthropic' | 'gemini';

export interface AiConfig {
  provider: Provider;
  apiKey: string;
  model?: string;
}

export const PROVIDERS: { id: Provider; label: string; defaultModel: string; keyHint: string }[] = [
  { id: 'openai', label: 'OpenAI', defaultModel: 'gpt-4o-mini', keyHint: 'sk-…' },
  { id: 'anthropic', label: 'Anthropic (Claude)', defaultModel: 'claude-3-5-haiku-latest', keyHint: 'sk-ant-…' },
  { id: 'gemini', label: 'Google Gemini', defaultModel: 'gemini-1.5-flash', keyHint: 'AIza…' },
];

function systemPrompt(scan: ParsedScan): string {
  return (
    `You are a cybersecurity assistant helping analyze an Nmap scan. ` +
    `Answer using the scan context below. Be accurate and practical; distinguish CONFIRMED ` +
    `findings from POTENTIAL (version-associated) ones, and never claim exploitation was proven ` +
    `unless the scan says so. If asked something the scan doesn't cover, say so.\n\n` +
    buildScanContext(scan)
  );
}

/** Send a chat turn to the selected provider. Returns the assistant reply text. */
export async function askAi(
  cfg: AiConfig,
  scan: ParsedScan,
  history: ChatMsg[],
  userMessage: string
): Promise<string> {
  const sys = systemPrompt(scan);
  const model = cfg.model || PROVIDERS.find((p) => p.id === cfg.provider)!.defaultModel;
  if (cfg.provider === 'openai') return openai(cfg.apiKey, model, sys, history, userMessage);
  if (cfg.provider === 'anthropic') return anthropic(cfg.apiKey, model, sys, history, userMessage);
  return gemini(cfg.apiKey, model, sys, history, userMessage);
}

async function openai(key: string, model: string, sys: string, history: ChatMsg[], msg: string): Promise<string> {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model,
      messages: [{ role: 'system', content: sys }, ...history, { role: 'user', content: msg }],
      temperature: 0.3,
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `OpenAI error ${res.status}`);
  return data.choices?.[0]?.message?.content?.trim() || '(empty response)';
}

async function anthropic(key: string, model: string, sys: string, history: ChatMsg[], msg: string): Promise<string> {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true',
    },
    body: JSON.stringify({
      model,
      max_tokens: 1024,
      system: sys,
      messages: [...history, { role: 'user', content: msg }],
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `Anthropic error ${res.status}`);
  return data.content?.[0]?.text?.trim() || '(empty response)';
}

async function gemini(key: string, model: string, sys: string, history: ChatMsg[], msg: string): Promise<string> {
  const contents = [
    ...history.map((h) => ({ role: h.role === 'assistant' ? 'model' : 'user', parts: [{ text: h.content }] })),
    { role: 'user', parts: [{ text: msg }] },
  ];
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: sys }] },
        contents,
        generationConfig: { temperature: 0.3 },
      }),
    }
  );
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `Gemini error ${res.status}`);
  return data.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '(empty response)';
}
