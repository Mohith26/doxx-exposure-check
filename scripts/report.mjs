// Headline numbers from data/account.json using the same code as the page.
// node scripts/report.mjs -> data/results.json (committed; a test checks it matches)
import { readFileSync, writeFileSync } from 'node:fs';
import { summarize } from '../src/exposure.js';

export function headline(data) { return summarize(data); }

if (import.meta.url === `file://${process.argv[1]}`) {
  const data = JSON.parse(readFileSync(new URL('../data/account.json', import.meta.url)));
  const out = headline(data);
  writeFileSync(new URL('../data/results.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
  console.log(JSON.stringify(out, null, 2));
}
