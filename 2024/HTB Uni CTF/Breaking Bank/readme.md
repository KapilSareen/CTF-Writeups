## Description

In the sprawling digital expanse of the Frontier Cluster, the Frontier Board seeks to cement its dominance by targeting the cornerstone of interstellar commerce: Cluster Credit, a decentralized cryptocurrency that keeps the economy alive. With whispers of a sinister 51% attack in motion, the Board aims to gain majority control of the Cluster Credit blockchain, rewriting transaction history and collapsing the fragile economy of the outer systems. Can you hack into the platform and drain the assets for the financial controller?


🔗 [Challenge source](./web_breaking_bad.zip)

---

## Overview

This challenge revolves around a **Crypto-Bank** website where users can form connections and conduct cryptocurrency transactions. The ultimate goal? Impersonate the `financial controller` with the email `financial-controller@frontier-board.htb` and drain their `CLCR` tokens to capture the flag.

---

## Solution

### Understanding the Security Flaw

The JWT (JSON Web Token) verification mechanism contains exploitable flaws. Here’s the code snippet that validates the token:

```js
export const verifyToken = async (token) => {
    try {
        const decodedHeader = jwt.decode(token, { complete: true });
        if (!decodedHeader || !decodedHeader.header) {
            throw new Error('Invalid token: Missing header');
        }
        const { kid, jku } = decodedHeader.header;
        if (!jku) {
            throw new Error('Invalid token: Missing header jku');
        }
        // TODO: is this secure enough?
        if (!jku.startsWith('http://127.0.0.1:1337/')) {
            throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
        }
        if (!kid) {
            throw new Error('Invalid token: Missing header kid');
        }
        if (kid !== KEY_ID) {
            return new Error('Invalid token: kid does not match the expected key ID');
        }
        let jwks;
        try {
            const response = await axios.get(jku);
            if (response.status !== 200) {
                throw new Error(`Failed to fetch JWKS: HTTP ${response.status}`);
            }
            jwks = response.data;
        } catch (error) {
            throw new Error(`Error fetching JWKS from jku: ${error.message}`);
        }
        if (!jwks || !Array.isArray(jwks.keys)) {
            throw new Error('Invalid JWKS: Expected keys array');
        }
        const jwk = jwks.keys.find((key) => key.kid === kid);
        if (!jwk) {
            throw new Error('Invalid token: kid not found in JWKS');
        }
        if (jwk.alg !== 'RS256') {
            throw new Error('Invalid key algorithm: Expected RS256');
        }
        if (!jwk.n || !jwk.e) {
            throw new Error('Invalid JWK: Missing modulus (n) or exponent (e)');
        }
        const publicKey = jwkToPem(jwk);
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return decoded;
    } catch (error) {
        console.error(`Token verification failed: ${error.message}`);
        throw error;
    }
};
```

#### JWT Spoofing

The code extracts kid and jku values from the token. Here’s what they mean:

- kid: The key ID used to validate the token’s digital signature.
- jku: The URL providing the JSON-encoded public keys for verification.

To bypass this, we’ll:

- Retrieve the kid value from /.well-known/jwks.json.
- Host a custom jwks.json on a static hosting platform, such as https://temp.staticsave.com.

#### Steps to Generate the RSA Key Pair

1. **Generate a private key**:
    ```bash
    openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
    ```
2. **Extract the public key**:
    ```bash
    openssl rsa -pubout -in private_key.pem -out public_key.pem
    ```

3. **Convert the modulus (n) to Base64** using an online tool.

---

Your `jwks.json` should look like this:

```json
{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "kid": "123e4567-e89b-12d3-a456-426614174000",
      "kty": "RSA",
      "n": "<BASE64_ENCODED_MODULUS>",
      "use": "sig"
    }
  ]
}
```
#### Bypassing the jku Check

The current implementation restricts jku to `http://127.0.0.1:1337/`. However, there’s an open redirect vulnerability in `/api/analytics/redirect`:

```js
    fastify.get('/redirect', async (req, reply) => {
        const { url, ref } = req.query;

        if (!url || !ref) {
            return reply.status(400).send({ error: 'Missing URL or ref parameter' });
        }
        // TODO: Should we restrict the URLs we redirect users to?
        try {
            await trackClick(ref, decodeURIComponent(url));
            reply.header('Location', decodeURIComponent(url)).status(302).send();
        } catch (error) {
            console.error('[Analytics] Error during redirect:', error.message);
            reply.status(500).send({ error: 'Failed to track analytics data.' });
        }
    });
```
Using this vulnerability, we can redirect the jku URL to a custom one:
```
http://127.0.0.1:1337/api/analytics/redirect?url=https://temp.staticsave.com/675c4d3d55fac.json&ref=0
```
Now, the `jku` URL will point to our custom `jwks.json` file.
Forging the JWT Token

To create a spoofed token, I used the following [Python script](./token.py). This allowed me to forge a valid JWT using the manipulated `jwks.json` file.

#### The OTP Bypass

There was an additional catch—a One-Time Password (OTP) required to complete the transaction. The relevant code for the OTP check was as follows:
```js
if (!otp.includes(validOtp)) {
    reply.status(401).send({ error: 'Invalid OTP.' });
    return;
}
```
This check uses the `.includes()` method, indicating that the OTP is treated as an array. To bypass it, I brute-forced the OTP by sending an array of all possible four-digit numbers (1000-9999). I automated this process using the final [Python script](./solve.py), and it worked like a charm!

Got the flag—definitely a fun challenge!
