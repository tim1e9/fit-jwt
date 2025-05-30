# fit-jwt
A zero-dependency JavaScript library for working with JWT and OIDC.

**NOTE:** If you're looking for a complete, OAuth-compliant client, this isn't it.
Instead, this library implements a subset of the specification. The purpose
of this subset is to simplify the developer experience, avoid exposing unused code
to potential security issues, and to make things cleaner. But with that said, this
isn't for everyone. If you're not sure, you should probably ask someone you trust
before going any further.

## How to use it

Install the package with `npm install fit-jwt`. Then, add code to your project as necessary.

**NOTE** A full example exists in the `./_samples` directory. It outlines
everything required to use this library - including application flows and environment variables.

## Code Coverage (optional)

This project used [c8](https://www.npmjs.com/package/c8) for a brief code coverage assessment.
However, to keep this a zero dependency library, it was removed. (The assumption is that a
project will have it's own code coverage suite of tools.) However, it can be re-enabled:

```bash
npm install --save-dev c8
```

Update `package.json` to:
```
"scripts": {
    "test": "c8 --clean --reporter=text --reporter=html node --test"
}
```

Now it's back.

## How to build it
This package can be built and pushed to an NPM registry, such as Verdaccio.

To use it,
Run npm pack
Run npm publish --registry http://localhost:4873

