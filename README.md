https://datatracker.ietf.org/doc/html/rfc8017#page-33
main() program calls the routines to generate PKCS 1.5 signature and be able to verify it. 
This will be our baseline.
Write a function to generate a hash on M (generating mHash). Then write a function to generate M’ by adding the padding in front of mHash, and appending a “salt”. 
After message M’ is ready, run the hash again to generate H. In addition, generate DB, which involves XORing with MGF (mask generation function to produce maskedDB. 
Finally I put maskedDB, H, and bc bits together to form EM.

Test vectors to validate the implementation. 
Used python (or other crypto libraries) to generate test vectors.
