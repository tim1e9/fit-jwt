// test/utils.test.js
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getPublicKey,
  getEnvironmentVariables
} from '../utils.js';

import { setupTestEnvironment } from './setup.js';

test.before(async () => {
  await setupTestEnvironment();
  await getEnvironmentVariables();
});

test('getPublicKey throws if key not found', () => {
  assert.throws(() => getPublicKey('nonexistent'), /No key found/);
});

test('getEnvironmentVariables throws if env var is missing', async () => {
  const backup = process.env.CLIENT_ID;
  delete process.env.CLIENT_ID;

  await assert.rejects(() => getEnvironmentVariables(), /Not all environment variables/);

  process.env.CLIENT_ID = backup;
});

test('getPublicKey constructs a PEM from a valid fake JWKS entry', async () => {
  const originalFetch = global.fetch;

  const modulus = Buffer.from('abcd1234', 'utf8').toString('base64url');
  const exponent = Buffer.from([0x01, 0x00, 0x01]).toString('base64url'); // 65537

  global.fetch = async () => ({
    json: async () => ({
      keys: [
        {
          kid: 'test-key',
          kty: 'RSA',
          alg: 'RS256',
          use: 'sig',
          n: modulus,
          e: exponent
        }
      ]
    })
  });

  await getEnvironmentVariables(); // reload env with custom key

  const pem = getPublicKey('test-key');
  assert.ok(pem.includes('-----BEGIN RSA PUBLIC KEY-----'));
  assert.ok(pem.includes('-----END RSA PUBLIC KEY-----'));

  global.fetch = originalFetch; // ✅ restore original
});
