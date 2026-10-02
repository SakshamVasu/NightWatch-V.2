import { readFileSync } from 'node:fs';
import { parseNmap } from '../src/parser/index.ts';
const raw = readFileSync(process.argv[2], 'utf8');
const r = parseNmap(raw);
console.log('=== SCAN ===');
console.log(JSON.stringify(r.scan, null, 2));
console.log('=== STATS ===');
console.log(JSON.stringify(r.stats, null, 2));
console.log('=== HOSTS ===', r.hosts.length);
console.log(JSON.stringify(r.hosts, null, 2));
console.log('=== OPEN PORTS ===', r.ports.filter((p)=>p.state.startsWith('open')).length);
for (const p of r.ports.filter((p)=>p.state.startsWith('open'))) {
  console.log(`${p.port}/${p.protocol} ${p.state} svc=${p.service||''} | prod=${p.product||''} ver=${p.version||''} extra=${p.extra||''}`);
}
