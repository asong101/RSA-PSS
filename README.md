https://datatracker.ietf.org/doc/html/rfc8017#page-33

Goal: Extend the RSA functionality in NetX Crypto library. RSA is a widely used public-key cryptographic algorithm. The NetX Crypto library is designed for embedded systems and IoT devices as it thrives in resource-constrained environments. It provides hash functions (like SHA 256), big-number modular arithmetic, and RSA encryption/signing. Currently, the NetX crypto library supports PKCS 1.5 (a digital signature algorithm based on RSA). The goal is to upgrade it to PKCS 2.0, by adding a PSS to the RSA signature scheme. A PSS is a probabilistic signature scheme which adds randomness (salt), masks the internal structure, and can produce different signatures for the same message. The old PKCS 1.5 is a deterministic function, similar to the SHA 256, which will produce the same signature for the same message. The PKCS 2.0 uses SHA 256 in multiple places, and also appends randomized sequences for greater security, as a pre-processing step before generating a signature. Note for this specific use-case, all we care about is verifying the message is coming from the right sender. PKCS 2.0 is still very easy to verify, but much harder to imitate.

importkey.c
init, import, and manage key from PSA interface

signing.c
give the encoded message a signature using RSA private key
hash is the digest after using the SHA256 function

main.c
RSA-PSS encoding logic for pre-processing before signing
main() program calls the routines to generate PKCS 1.5 signature and be able to verify it. 
This will be our baseline.
- function to generate a hash on M (generating mHash). 
- function to generate M’ by adding the padding in front of mHash, and appending a “salt”. 
- After message M’ is ready, run the hash again to generate H. In addition, generate DB, which involves XORing with MGF (mask generation function) to produce maskedDB. 
- Finally put maskedDB, H, and bc bits together to form encoded message.

program lifecycle:

main.c -> importkey.c -> signing.c

