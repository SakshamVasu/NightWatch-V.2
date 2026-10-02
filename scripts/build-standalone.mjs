// Builds a single self-contained standalone.html that runs the *tested* parser
// in the browser with no npm/build step. React, Recharts and Babel load from CDN
// at runtime; the parser is transpiled from the same TS source the app uses.
import { stripTypeScriptTypes } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const P = (p) => join(root, 'src', 'parser', p);

// Order: util -> exploitation -> remediation -> core -> analyze -> report -> assistant -> aiClient.
const files = ['util.ts', 'exploitation.ts', 'remediation.ts', 'core.ts', 'analyze.ts', 'formats.ts', 'report.ts', 'localAssistant.ts', 'aiChat.ts'];

function toBrowserJs(src) {
  let js = stripTypeScriptTypes(src, { mode: 'transform' });
  // Drop ESM import lines and `export { ... }` re-exports (names stay in scope
  // because everything is concatenated into one IIFE), and strip the leading
  // `export`/`export default` keyword from declarations.
  js = js
    .split('\n')
    .filter((l) => !/^\s*import\s/.test(l))
    .filter((l) => !/^\s*export\s*\{[^}]*\}\s*;?\s*$/.test(l))
    .filter((l) => !/^\s*export\s+(type|interface)\b/.test(l))
    .map((l) => l.replace(/^(\s*)export\s+default\s+/, '$1').replace(/^(\s*)export\s+/, '$1'))
    .join('\n');
  return js;
}

let parserJs = '';
for (const f of files) {
  const src = readFileSync(P(f), 'utf8');
  parserJs += `\n/* ==== ${f} ==== */\n` + toBrowserJs(src) + '\n';
}

// The UI (a compact single-file React app) is authored inline in the template.
const template = readFileSync(join(here, 'standalone.template.html'), 'utf8');
const logoUri = readFileSync(join(root, 'src', 'components', 'logo.ts'), 'utf8')
  .match(/'(data:image\/png;base64,[^']+)'/)[1];
const out = template
  .replace('/*__PARSER__*/', parserJs)
  .replace('__LOGO_URI__', logoUri);
writeFileSync(join(root, 'standalone.html'), out);
console.log('Wrote standalone.html (' + (out.length / 1024).toFixed(1) + ' KB)');
