// @ts-check intermittently, because this is actually JavaScript
import { randomBytes, createHash } from 'crypto';
import { getEnvironmentVariables, getOidcProviderURL, getTokenURL, isValidSignature } from './utils.js';

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
        const jwtTokens = new JwtTokens(allData.access_token,
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

// This can get confusing. This is called to access resources, so we really need
// the access token. However, we're grabbing the current user's details, so it feels
// like we should use the id_token. Resist the urge to use the id_token. What a mess.
const getUserFromToken = (accessToken) => {
    const validToken = isTokenValid(accessToken, "access_token")
    if ( !validToken) {
        return null;
    }
    const [_jwtHeader, jwtPayload, _jwtSignature] = accessToken.split('.');
    const user = JSON.parse(Buffer.from(jwtPayload, 'base64url').toString());
    return user;
}

const isTokenValid = (curToken, tokenType) => {
    try {
        if (!["id_token", "access_token"].includes(tokenType)) {
            throw new Error('Invalid token type, only id_token and access_token are allowed.')
        }
        const [_jwtHeader, jwtPayload, _jwtSignature] = curToken.split('.');
        if (!isValidSignature(curToken)) {
            throw new Error('The JSON signature is not valid.')
        }

        const jwtDetails = JSON.parse(Buffer.from(jwtPayload, 'base64url').toString());

        // The issuer is the host, but a simple way to test is to see how it compares to the JWKS URL
        if (ev.JWKS_URL.substring(jwtDetails.iss) < 0) {
            throw new Error(`The issuer for the token is different from what is expected.`)
        }

        // More checks: An attacker could replay a valid token from another client or issuer
        // Make sure the returned values match what's expected
        if ((tokenType == "id_token") && (jwtDetails.aud != ev.CLIENT_ID)) {
            throw new Error(`The token audience doesn't match what was sent`)
        }

        // Check to see if the token has expired
        const expTime = jwtDetails.exp * 1000;  // The time is in seconds; convert it to milliseconds
        const curTime = new Date().getTime();
        if (expTime < curTime) {
            throw new Error('The token has expired');
        }

        return true;
    } catch(exc) {
        console.error(`Error parsing the jwtDetails from a token: ${exc.message}`);
    }
    return false;
}

export {
    PkceDetails,
    JwtTokens,
    init,
    getAuthURL,
    getPkceDetails,
    getJwtToken,
    refreshJwtToken,
    getUserFromToken,
    isTokenValid
}