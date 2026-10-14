import fs from 'node:fs';
import path from 'node:path';

export function checkSoakAuthorization(plan, compiled, now) {
  const deadline = Math.min(Number(plan.auth_deadline_unix), Number(compiled.authorization_expires_at_unix));
  const required = 7200 + 300;
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(deadline)) {
    return {gate: 'BLOCKED', reason: 'missing_verified_authorization_deadline'};
  }
  return {gate: deadline - now >= required ? 'PASS' : 'BLOCKED', reason: deadline - now >= required ? 'static_authorization_covers_soak' : 'renewal_required_before_two_hour_soak', remaining_seconds: deadline - now, required_seconds: required, deadline_unix: deadline, now_unix: now};
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const [directory, output] = process.argv.slice(2);
  if (!directory || !output) throw new Error('usage: node soak-preflight.mjs <run-directory> <new-result.json>');
  if (fs.existsSync(output)) throw new Error('refusing to replace prior preflight evidence');
  const read = name => JSON.parse(fs.readFileSync(path.join(directory, name)));
  const result = checkSoakAuthorization(read('plan.json'), read('compiled-control.json'), Math.floor(Date.now() / 1000));
  fs.writeFileSync(output, JSON.stringify(result, null, 2), {mode: 0o600});
  console.log(`soak authorization ${result.gate}: ${result.reason}`);
  if (result.gate !== 'PASS') process.exitCode = 1;
}
