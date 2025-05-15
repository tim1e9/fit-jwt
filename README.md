# fit-jwt
A zero-dependency JavaScript library for working with JWT

**NOTE:** If you're looking for a complete, OAuth-compliant client, this isn't it.
Instead, this library implements a subset of the specification. The purpose
of this subset is to simplify the developer experience, avoid exposing unused code
to potential security issues, and to make things cleaner. But with that said, this
isn't for everyone. If you're not sure, you should probably ask someone you trust
before going any further.

## How to use it

Install the package with `npm install fit-jwt`. Then, add code to your project as necessary.

**NOTE** A full example exists in the `./_samples` directory. It outlines
everything required to use this library - including application flow.


## How to build it
This package can be built and pushed to an NPM registry, such as Verdaccio.

To use it,
Run npm pack
Run npm publish --registry http://localhost:4873

## Configuration variables

There are a number of environment variables required. This is due to the nature of
how different OAuth providers exchange information. (Example: Keycloak has the concept
of a "relm", while other providers to not.)

For this reason, environment variable details are stored within the samples.