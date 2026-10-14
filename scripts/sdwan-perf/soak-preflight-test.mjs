import assert from 'node:assert/strict';
import {checkSoakAuthorization} from './soak-preflight.mjs';

const now = 1000;
assert.equal(checkSoakAuthorization({auth_deadline_unix: now + 3600}, {authorization_expires_at_unix: now + 10800}, now).gate, 'BLOCKED');
assert.equal(checkSoakAuthorization({auth_deadline_unix: now + 10800}, {authorization_expires_at_unix: now + 3600}, now).gate, 'BLOCKED');
assert.equal(checkSoakAuthorization({auth_deadline_unix: now + 7500}, {authorization_expires_at_unix: now + 7500}, now).gate, 'PASS');
assert.equal(checkSoakAuthorization({}, {}, now).gate, 'BLOCKED');
assert.equal(checkSoakAuthorization({auth_deadline_unix: now - 1}, {authorization_expires_at_unix: now + 10800}, now).gate, 'BLOCKED');
console.log('PASS: effective static authority must cover 7200 seconds plus 300 seconds safety; one-hour cap, expiry and missing evidence blocked');
