# Using fit-jwt

This sample application demonstrates how to use fit-jwt in a NodeJS application.

Before starting, be sure that `fit-jwt` has been published to either a public NPM
registry. (Or, to a private one, which is identified by the presence of a `.npmrc` file.)

## Running the Application

Steps to run:
1. Install the dependencies ( `npm i` )
2. Verify that all environment variables are properly defined. (See environment variables below)
3. Start the application ( `npm start` )
4. In a browser, navigate to the main page: http://localhost:3000/ The response should
   be a simple JSON doc which reads:
   ```
   {
     msg: 'The index is not protected, so everyone should be able to see this.'
   }
   ```
5. To force authentication, next navigate to the login page: http://localhost:3000/login
6. You should be redirected to the OAuth provider. From there, provide your credentials
7. If the credentials are correct, the browser should show the original page, but with
   the authenticated details showing. (Remember - this is a sample. You wouldn't normally do this.)
8. To verify that the credentials are "real", navigate to http://localhost:3000/aboutme
   This should display information that was returned by the OAuth provider. **HOWEVER**, since
   this isn't a real application, and client-side persistence isn't implemented, you may need
   to copy the ID token, and use it in the following curl command:
   ```
   export TMP_AUTH=<place the idtoken value here>
   curl -H "Authorization: $TMP_AUTH" http://localhost:3000/aboutme
   ```
   The output should be something similar to the following:
   ```
   {
     "msg": {
         "exp": 1747231259,
         "iat": 1747230959,
         "auth_time": 1747230705,
         "name": "Firstname Lastname",
         "preferred_username": "kpowers",
         "given_name": "Firstname",
         "family_name": "Lastname",
         "email": "kpowers@example.com"
      }
   }
   ```
9. For some applications, it may be valuable to include a logout functionality. Although
   nothing happens within this application, the logout route has been included for 
   demonstration purposes.
10. It is also possible to refresh the JWT token by navigating to: http://localhost:3000/testrefresh
    After navigating to this URL, the refreshed tokens should be visible.

## Environment Variables

There are a surprising number of fields that can change from implementation to implementation.
It's a bit much, but then again, what isn't a "bit much" in software these days? This section
attempts to highlight what's needed with the various OAuth providers.

Variables specific to the sample application:
- **COOKIE_NAME** The name of the cookie which shares information between the OAuth server and the sampel app
- **JWT_HEADER_NAME** The header the sample application inspects to locate the JWT


Variables - all providers:

- **OAUTH_HOST** The hostname of the OAuth server. For local development, it's probably `http://localhost:8080`
- **CLIENT_ID** The OAuth Client ID. Provided by the OAuth provider. (This can be human readable.)
- **CLIENT_SECRET** The OAuth Secret. Also provided by the OAuth provider. (A long string of characters)
- **OAUTH_STATE** A string which helps prevent cross-site scripting attacks. It should be a string.
- **OAUTH_RESP_TYPE** This should be set to "code". However, other flows are supported.
- **OAUTH_JWT_PUBLIC_KEY** The public key from the OAuth server. Some OAuth / JWT implementations
  automatically retrieve this. However, in keeping in line with a "fit" approach, that feautre
  has not yet been needed. To find the public key, refer to the OAuth provider's documentation.
  For keycloak, it will be something like: http://localhost:8080/realms/somerealm


Variables - KeyCloak

- **KEYCLOAK_REALM_NAME** The KeyCloak "Realm" (or namespace) for this particular applicaiton. (I don't
  name these things, I just use 'em.)
- **KEYCLOAK_SCOPE** A Keycloak concept for aggregating a number of settings and configurations together. (This will be used to construct the authentication URL.)

To find the KeyCloak certificate used to sign the JWT Token:
http://MY_KEYCLOAK_HOST_AND_PORT/realms/myrealm


## References
PKCE - (https://datatracker.ietf.org/doc/html/rfc7636) requires these three values:
       Code Challenge, Code Challenge Method, and Code Verifier
       
A nice explanation: https://pazel.dev/teach-me-pkce-proof-key-for-code-exchange-in-5-minutes
