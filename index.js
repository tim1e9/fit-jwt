// @ts-check

import { randomBytes, createHash, createVerify } from 'crypto';
import { getEnvironmentVariables, getOidcProviderURL, getTokenURL } from './utils.js';

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

const ev = getEnvironmentVariables();
const AUTH_URL = getOidcProviderURL(ev);
const tokenURL = getTokenURL(ev);

// Some implementations don't validate the signature. That would be a pretty big mistake
const isValidSignature = (rawToken) => {
    try {
        const [ rawTokenHeader, rawTokenPayload, rawTokenSignature] = rawToken.split('.');
        const tokenSignature = Buffer.from(rawTokenSignature, 'base64');

        // As of now, only RS256 is supported. Consider adding support for HS256
        const tokenHeader = JSON.parse(Buffer.from(rawTokenHeader, 'base64').toString('utf-8'));
        if (tokenHeader.alg != "RS256") {
            console.error(`Only the RS256 algorithm is supported. Current algorithm: ${tokenHeader.alg}`)
            return false;
        }

        // Reconstitute the header and payload
        const contentToVerify = `${rawTokenHeader}.${rawTokenPayload}`
        const rs256verifier = createVerify('RSA-SHA256');
        rs256verifier.update(contentToVerify);
        const result = rs256verifier.verify(ev.JWT_PUBLIC_KEY, tokenSignature);
        return result;
    } catch(exc) {
        console.error(`Error verifying the JWT signature: ${exc.message}`);
        return false;
    }
}

// PKCE requires these three values: Code Challenge, Code Challenge Method, and Code Verifier
const getPkceDetails = (pkceMethod ) => {
    const codeVerifier = randomBytes(32).toString('base64')
            .replace(/=/g, '').replace(/\+/g,'-',).replace(/\//,'_');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64')
            .replace(/=/g, '').replace(/\+/g,'-',).replace(/\//,'_');

    // If the pkecMethod is 'plain' then don't encode. Other wise, use S256
    const pkce = new PkceDetails(codeVerifier,
        (pkceMethod == 'plain') ? codeVerifier : codeChallenge,
         pkceMethod);
    return pkce;
}

// Note: It's a bad idea to skip PKCE. Don't do it. In fact, getJwtToken() kinda assumes you're using it.
const getAuthURL = (pkceDetails) => {
    return (!pkceDetails) ? AUTH_URL :
        AUTH_URL + `&code_challenge=${pkceDetails.codeChallenge}&code_challenge_method=${pkceDetails.method}`
}

const getJwtToken = async (code, codeVerifier) => {
    // The token request requires authentication (naturally). Unfortunately, it's not obvious
    // that it consists of the base64-encoded client ID and client secret. Now it is obvious.
    const base64Creds = Buffer.from(`${ev.CLIENT_ID}:${ev.CLIENT_SECRET}`).toString('base64');
    const authHeader = 'Basic ' + base64Creds;

    let response;
    try {
        const formData = new URLSearchParams();
        formData.append("code", code);
        formData.append("grant_type", 'authorization_code');
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

    } catch(exc) {
        console.log(`Error: Exception thrown when attempting to obtain a token: ${exc.message}`);
        return null;
    }

    // Format the response to include the three retrieved tokens
    const allData = await response.json();
    const jwtTokens = new JwtTokens(allData.accessToken,
        allData.id_token, allData.refresh_token);
    return jwtTokens;
}

const refreshJwtToken = async (refreshToken) => {
    const base64Creds = Buffer.from(`${ev.CLIENT_ID}:${ev.CLIENT_SECRET}`).toString('base64');
    const authHeader = 'Basic ' + base64Creds;

    let response;
    try {
        const formData = new URLSearchParams();
        formData.append("grant_type", 'refresh_token');
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

    } catch(exc) {
        console.log(`Error: Exception thrown when attempting to refresh a token: ${exc.message}`);
        return null;
    }

    // Format the response to include the three retrieved tokens
    const allData = await response.json();
    const jwtTokens = new JwtTokens(allData.accessToken,
        allData.id_token, allData.refresh_token);
    return jwtTokens;
}

const getUserFromToken = (accessToken, verifyTimestamp = true, verifySignature = true) => {
    try {
        const [_jwtHeader, jwtPayload, _jwtSignature] = accessToken.split('.');
        if (verifySignature) {
            if (!isValidSignature(accessToken)) {
                console.error('ERROR: JSON Signature is not valid!')
                return null;
            }
        } else {
            console.warn('WARNING: Signature not verified. THIS IS A REALLY BAD IDEA!');
        }

        const user = JSON.parse(Buffer.from(jwtPayload, 'base64').toString());

        if (verifyTimestamp) {
            // Check to see if the token has expired
            const expTime = user.exp * 1000;  // The time is in seconds; convert it to milliseconds
            const curTime = new Date().getTime();
            if (expTime < curTime) {
                console.log('The token has expired');
                return null;
            }
        }

        return user;
    } catch(exc) {
        console.log(`Error parsing the user from a token: ${exc.message}`);
    }
    return null;
}

export {
    PkceDetails,
    JwtTokens,
    getAuthURL,
    getPkceDetails,
    getJwtToken,
    refreshJwtToken,
    getUserFromToken
}