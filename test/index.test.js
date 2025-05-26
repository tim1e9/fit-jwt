import test from 'node:test';
import assert from 'node:assert/strict';
import {
  init,
  PkceDetails,
  JwtTokens,
  getUserFromToken,
  getJwtToken,
  refreshJwtToken
} from '../index.js';
import { setupTestEnvironment } from './setup.js';

test.before(async () => {
  await setupTestEnvironment();
  await init();
});

test('PkceDetails and JwtTokens store data correctly', () => {
  const pkce = new PkceDetails('verifier', 'challenge', 'plain');
  assert.strictEqual(pkce.codeVerifier, 'verifier');
  assert.strictEqual(pkce.codeChallenge, 'challenge');
  assert.strictEqual(pkce.method, 'plain');

  const jwt = new JwtTokens('a', 'b', 'c');
  assert.strictEqual(jwt.accessToken, 'a');
  assert.strictEqual(jwt.idToken, 'b');
  assert.strictEqual(jwt.refreshToken, 'c');
});

test('getJwtToken returns tokens from mocked fetch', async () => {
  global.fetch = async () => ({
    json: async () => ({
      accessToken: 'tokenA',
      id_token: 'tokenB',
      refresh_token: 'tokenC'
    }),
  });

  const token = await getJwtToken('code123', 'verifier123');
  assert.strictEqual(token.accessToken, 'tokenA');
  assert.strictEqual(token.idToken, 'tokenB');
  assert.strictEqual(token.refreshToken, 'tokenC');
});

test('refreshJwtToken returns tokens from mocked fetch', async () => {
  global.fetch = async () => ({
    json: async () => ({
      accessToken: 'refA',
      id_token: 'refB',
      refresh_token: 'refC'
    }),
  });

  const token = await refreshJwtToken('refresh-123');
  assert.strictEqual(token.accessToken, 'refA');
  assert.strictEqual(token.idToken, 'refB');
  assert.strictEqual(token.refreshToken, 'refC');
});

test('getJwtToken throws on fetch failure', async () => {
  global.fetch = async () => { throw new Error('mocked fetch error') };
  await assert.rejects(() => getJwtToken('code', 'verifier'), /Exception thrown when attempting to obtain a token/);
});

test('getJwtToken throws if JSON response is invalid', async () => {
  global.fetch = async () => ({ json: () => { throw new Error('bad json') } });
  await assert.rejects(() => getJwtToken('code', 'verifier'), /Exception thrown when attempting to obtain a token/);
});

test('getJwtToken handles missing tokens gracefully', async () => {
  global.fetch = async () => ({ json: async () => ({}) });
  const result = await getJwtToken('code', 'verifier');
  assert.ok(result instanceof JwtTokens);
  assert.strictEqual(result.accessToken, undefined);
  assert.strictEqual(result.idToken, undefined);
  assert.strictEqual(result.refreshToken, undefined);
});

test('refreshJwtToken throws on fetch failure', async () => {
  global.fetch = async () => { throw new Error('mocked refresh error') };
  await assert.rejects(() => refreshJwtToken('refresh-token'), /Exception thrown when attempting to refresh a token/);
});

test('getUserFromToken returns null if token is invalid', () => {
  // Three segments but fails isTokenValid
  const token = 'header.payload.sig';
  const result = getUserFromToken(token); // verify=true
  assert.strictEqual(result, null);
});

test('getUserFromToken returns null if payload is malformed JSON', () => {
  // base64url for `this is not json`
  const payload = Buffer.from('this is not json').toString('base64url');
  const token = `header.${payload}.sig`;
  const result = getUserFromToken(token, false, false); // skip validation
  assert.strictEqual(result, null);
});
