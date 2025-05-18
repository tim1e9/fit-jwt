export class PkceDetails {
  constructor(codeVerifier: string, codeChallenge: string, method: string);
  codeVerifier: string;
  codeChallenge: string;
  method: string;
}

export class JwtTokens {
  constructor(accessToken: string, idToken: string, refreshToken: string);
  accessToken: string;
  idToken: string;
  refreshToken: string;
}

export function getAuthURL(pkceDetails?: PkceDetails): string;

export function getPkceDetails(pkceMethod: string): PkceDetails;

export function getJwtToken(code: string, codeVerifier: string): Promise<JwtTokens>;

export function refreshJwtToken(refreshToken: string): Promise<JwtTokens>;

export function getUserFromToken(
  accessToken: string,
  verifyTimestamp?: boolean,
  verifySignature?: boolean
): Record<string, any> | null;
