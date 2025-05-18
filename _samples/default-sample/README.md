# Using fit-jwt

This sample application demonstrates how to use fit-jwt in a NodeJS application.

Before starting, be sure that `fit-jwt` has been published to either a public NPM
registry. (Or, to a private one, which is identified by the presence of a `.npmrc` file.)

## Running the Application

Steps to run:
1. Install the dependencies ( `npm i` )
2. Verify that all environment variables are properly defined.
   (See the environment variable sample files for more details.)
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


## References
PKCE - (https://datatracker.ietf.org/doc/html/rfc7636) requires these three values:
       Code Challenge, Code Challenge Method, and Code Verifier
       
A nice explanation: https://pazel.dev/teach-me-pkce-proof-key-for-code-exchange-in-5-minutes
