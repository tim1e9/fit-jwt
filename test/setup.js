// test/setup.js
export async function setupTestEnvironment() {
  process.env['AUTH_ENDPOINT'] = 'https://example.com/auth';
  process.env['TOKEN_ENDPOINT'] = 'https://example.com/token';
  process.env['OAUTH_REDIR_URI'] = '/auth/callback';
  process.env['CUR_HOSTNAME'] = 'https://localhost:3000';
  process.env['CLIENT_ID'] = 'abc123';
  process.env['CLIENT_SECRET'] = 'secret';
  process.env['OAUTH_STATE'] = 'xyz';
  process.env['OAUTH_SCOPE'] = 'openid email';
  process.env['JWKS_URL'] = 'http://localhost:9999/mock-jwks';

  global.fetch = async () => ({
    json: async () => ({ keys: [] })
  });
}
