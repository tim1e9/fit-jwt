import express from 'express';
import 'dotenv/config'

import { getAuthURL, getPkceDetails, getJwtToken, refreshJwtToken, getUserFromToken } from 'fit-jwt';
const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));

// Note: This sample code stores PKCE details in a cookie to maintain them across
// multiple calls. It's not encoded, and not really the best approach. It's probably
// best to use a temporary session, and keep things even more secure.
// This is done for the sample only.
import cookieParser from 'cookie-parser';
app.use(cookieParser());
const cookieName = process.env.COOKIE_NAME;
const jwtHeaderName = process.env.JWT_HEADER_NAME;

// ------------------- Authn / Authz Endpoints --------------------------------

app.get('/login', (_req, res) => {
    // We are using PKCE, and we are also mandating the S256 hash of the PKCE code
    const pkceDetails = getPkceDetails('S256');
    res.cookie(cookieName, JSON.stringify(pkceDetails));
    const url = getAuthURL(pkceDetails);
    res.redirect(url);
});

// This is called after the user has authenticated. Extract the code,and exchange it for a JWT token.
app.get('/auth/callback', async (req, res) => {
    const code = req.query.code;
    // Extract the code challenge from the cookie
    const rawCookie = req.cookies[cookieName];
    if (!rawCookie) {
        res.json({status: "cookie missing"})
    } else {
        const pkceDetails = JSON.parse(rawCookie);
        const jwtComponents = await getJwtToken(code, pkceDetails.codeVerifier);
    
        // Clear the cookie - it's no longer needed
        res.clearCookie(cookieName);
    
        // Redirect this to the main authenticated landing page, but include the token(s)
        res.json(jwtComponents)
    }
});

// Logout callback. This may be called when a user explicitly logs out, but it's generally not used.
// Remember: JWTs don't really get invalidated; they simply expire over time. Of course, we can
// add custom code to simulate JWT invalidation, but it's a slippery slope
app.get('/logout/callback', (_req, res) => {
    res.redirect('/');
});

// This should be used as Express middleware before every secure route is called. It will attempt
// to verify the user details, and if valid, place those details within the request.
const checkAuthenticated = (req, res, next) => {
    const token = req.header(jwtHeaderName)
    if (!token) {
        res.status(401).json({message: 'User does not have credentials'});
        return;
    }
    const user = getUserFromToken(token);
    if (!user) {
        res.status(401).json({message: 'User details are missing. Does the user have valid credentials?'});
        return;
    }
    req.user = user;
    return next() 
}
// ----------------------------------------------------------------------------

//The default, unprotected route
app.get('/',function(_req,res){
    res.send({msg: 'The index is not protected, so everyone should be able to see this.'});
});


app.get('/aboutme', checkAuthenticated, (req, res) => {
    // If the user details aren't found, this code will never run. (See checkAuthenticated())
    const user = req.user;
    res.send({msg: user});
});

app.get('/testrefresh', async (req, res) => {
    // Test the ability to refresh a JWT token. (This is just used for completeness. Consider
    // a far more comprehensive workflow for refreshing a token in a real app.)
    const token = req.header("myrefreshtoken");
    const newDetails = await refreshJwtToken(token);
    res.send({msg: newDetails});
});


// ------------------------- Standard NodeJS Scaffolding ----------------------

const port = process.env.NODEJS_PORT ? process.env.NODEJS_PORT : 3000;

app.listen(port, () =>
  console.log(`Example app listening at http://localhost:${port}`)
);
