import { readFileSync } from 'node:fs';
const compose = readFileSync('compose.yaml', 'utf8');
const required = [
  'name: shadowops-chronicles',
  'chronicles-api:',
  'ghcr.io/evilsysadmin/chronicles-api@',
  'CHRONICLES_IMAGE_DIGEST',
  'read_only: true',
  'no-new-privileges:true',
  'cap_drop:',
  'mem_limit:',
  '127.0.0.1:18081:8080',
  'healthcheck:'
];
for (const item of required) if (!compose.includes(item)) throw new Error('Missing Compose safeguard: ' + item);
if (/chess-api:|chess-studio-api:/.test(compose)) throw new Error('Chess Studio is outside scope');
if (/image:\\s*[^\\n]*:(latest|main)\\b/.test(compose)) throw new Error('Mutable image tag');
console.log('Chronicles-only Compose contract OK');
