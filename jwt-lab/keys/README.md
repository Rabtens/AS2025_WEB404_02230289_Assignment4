# keys/

Demo RSA keypair for the RS256 / algorithm-confusion demonstrations.

- `private.pem` — used by the vulnerable server's `POST /rsa-login` to sign RS256 tokens.
- `public.pem` — the (intentionally public) verification key. Attack 03 abuses it
  as an HMAC secret against a server that doesn't pin the algorithm.

Regenerate with `npm run genkeys`. These are throwaway lab keys — never reuse them.
