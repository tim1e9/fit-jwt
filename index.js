// @ts-check intermittently, because this is actually JavaScript
import { randomBytes, createHash } from 'crypto';
import { getEnvironmentVariables, getOidcProviderURL, getTokenURL, isTokenValid } from './utils.js';

// ----- A class / data type for the PKCE details -----
class PkceDetails {
    constructor(codeVerifier, codeChallenge, method) {
        this.codeVerifier = codeVerifier;
        this.codeChallenge = codeChallenge;
        this.method = method;
    }
}

// ----- A class / data type for the three types of tokens associated with JWT -----
class JwtTokens {
    constructor(accessToken, idToken, refreshToken) {
        this.accessToken = accessToken;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
    }
}

// It is critical to call this first. (It was originally at the top level, but that
// limited the options for writing unit tests.) I'm not sure if this is better or not. 
let ev, AUTH_URL, tokenURL;
const init = async () => {
  ev = await getEnvironmentVariables();
  AUTH_URL = getOidcProviderURL();
  tokenURL = getTokenURL();
};

// PKCE requires these three values: Code Challenge, Code Challenge Method, and Code Verifier
const getPkceDetails = (pkceMethod ) => {
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');

    // If the pkecMethod is 'plain' then don't encode. Other wise, use S256
    const pkce = new PkceDetails(codeVerifier,
        (pkceMethod == 'plain') ? codeVerifier : codeChallenge,
         pkceMethod);
    return pkce;
}

const getAuthURL = (pkceDetails) => {
  const params = new URLSearchParams({
    code_challenge: pkceDetails.codeChallenge,
    code_challenge_method: pkceDetails.method,
  });
  return `${AUTH_URL}&${params.toString()}`;
};

const getJwtToken = async (code, codeVerifier) => {
    // The token request requires authentication (naturally). Unfortunately, it's not obvious
    // that it consists of the url-encoded client ID and client secret. Now it is obvious.
    const base64Creds = Buffer.from(`${ev.CLIENT_ID}:${ev.CLIENT_SECRET}`).toString('base64url');
    const authHeader = 'Basic ' + base64Creds;

    let response;
    try {
        const formData = new URLSearchParams();
        formData.append("code", code);
        formData.append("grant_type", 'authorization_code');
        // @ts-ignore
        formData.append("client_id", ev.CLIENT_ID);
        formData.append("redirect_uri", ev.CUR_HOSTNAME + ev.OAUTH_REDIR_URI);
        formData.append("code_verifier", codeVerifier);

        response = await fetch(tokenURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader
            },
            body: formData.toString()
        });

        // Format the response to include the three retrieved tokens
        const allData = await response.json();
        const jwtTokens = new JwtTokens(allData.accessToken,
                                    allData.id_token, allData.refresh_token);
        return jwtTokens;

    } catch(exc) {
        const msg = `Error: Exception thrown when attempting to obtain a token: ${exc.message}`;
        console.error(msg);
        throw new Error(msg)
    }
}

const refreshJwtToken = async (refreshToken) => {
    let response;
    try {
        const base64Creds = Buffer.from(`${ev.CLIENT_ID}:${ev.CLIENT_SECRET}`).toString('base64url');
        const authHeader = 'Basic ' + base64Creds;
        const formData = new URLSearchParams();
        formData.append("grant_type", 'refresh_token');
        // @ts-ignore
        formData.append("client_id", ev.CLIENT_ID);
        formData.append("refresh_token", refreshToken);

        response = await fetch(tokenURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': authHeader
            },
            body: formData.toString()
        });

        // Format the response to include the three retrieved tokens
        const allData = await response.json();
        const jwtTokens = new JwtTokens(allData.accessToken,
                                allData.id_token, allData.refresh_token);
        return jwtTokens;

    } catch(exc) {
        const msg = `Error: Exception thrown when attempting to refresh a token: ${exc.message}`;
        console.error(msg);
        throw new Error(msg);
    }
}

const getUserFromToken = (accessToken) => {
    const validToken = isTokenValid(accessToken)
    if ( !validToken) {
        return null;
    }
    const [_jwtHeader, jwtPayload, _jwtSignature] = accessToken.split('.');
    const user = JSON.parse(Buffer.from(jwtPayload, 'base64url').toString());
    return user;
}

export {
    PkceDetails,
    JwtTokens,
    init,
    getAuthURL,
    getPkceDetails,
    getJwtToken,
    refreshJwtToken,
    getUserFromToken
}