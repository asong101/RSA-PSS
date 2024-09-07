#include "nx_crypto_sha2.h"
#include <stdint.h>
#include <stdio.h>

#define SHA256     1

#define SHA512     2



#define SUCCESS 0

#define FAILURE   1
/*
static uint64_t OS2IP(const unsigned char* encodedMessage) {
    uint64_t integer = 0;

    for (size_t i = 0; i < length; i++) {
        integer = pow(256, ) + (unsigned int)encodedMessage[i];
    }

    return integer;
}
*/
char message[] = "abcdefghijklmnopqrstuvwxyz";
char encoded_message[512];

static unsigned char* hash(char* message, int message_size, UCHAR *digest, int digest_size) {
    NX_CRYPTO_SHA256 my_sha256;
    //UINT algorithm;

    UINT ret;
    ret = _nx_crypto_sha256_initialize(&my_sha256, NX_CRYPTO_HASH_SHA256);

    if (ret != NX_CRYPTO_SUCCESS) {
        printf("failed to initialize SHA256 engine.\n");
    }

    ret = _nx_crypto_sha256_update(&my_sha256, message, message_size);

    if (ret != NX_CRYPTO_SUCCESS) {

        printf("Failed to update SHA256 message.\n");
    }

    //UCHAR digest[32];  // SHA256 digest output is 32 bytes
    //int *ptr = &digest[0];
    //printf(ptr);
    ret = _nx_crypto_sha256_digest_calculate(&my_sha256, digest, NX_CRYPTO_HASH_SHA256);

    if (ret != NX_CRYPTO_SUCCESS) {
        printf("Failed to obtain digest.\n");
    }
    
    //for (int i = 0; i < 32;i++)  printf(digest[i] + "\n");
    return digest;
}
/*
-Hash function type.  For now you can use the symbol SHA256 (which is defined as “1”).
-Message:  this is the message to be hashed.
-message_size:  Number of bytes in the message.
-encoded_message: Buffer space for storing the EM.
-em_size: Total size of the EM buffer space.
Your function (prepare_em()) shall never write more data into the buffer than the buffer size.
-Encoded_message_size:  this is the return value of the actual number of bytes of EM.
The length of the EM is likely smaller than the encoded_message buffer passed into the function.
*/
static void prepare_em(int type, char* message, int message_size, 
    char encoded_message[512], int em_size, int encoded_message_size) { //encoded_message_size 256

    //if (message > /*input limitation for the hash function*/) printf("Message too long\n");

    /* This buffer fills with the padding bytes.
    I believe the RFC spelled out how to compute the padding length and the exact size of Padding1. */
    int hLen = 32;
    int sLen = hLen; // or 0
    if (encoded_message_size < hLen + sLen + 2) printf("Encoding Error\n");
    //unsigned char mHash[32]; /* This buffer stores the hash output from the program you wrote.*/

    unsigned char mHash[32];
    hash(message, message_size, mHash, sizeof(mHash));
    unsigned char buffer_Padding1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    
    unsigned char salt[32]; /* Again the RFC specifies the size of the salt.*/
    for (int i = 0; i < sLen; i++) {
        salt[i] = (unsigned char)(rand() % 256);
    }
    
/* In C, you can allocate new memory space by calling “malloc” (remember after the buffer is used,
you must call “free” to release these buffers.

Once you fill in these 3 buffers, M’ is simply moving all 3 parts into one memory buffer:
unsigned char buffer_m_prime[/* Find the length of M’ *./

In the final step, you can use memcpy to move padding1, mHash, and salt into the M’ buffer.
During this step, the memory view may help you to visualize the buffer layout follows the RFC.*/

/* M' is an octet string of length 8 + hLen + sLen with eightinitial zero octets. */
//&M = buffer_Padding1 + hash(message, message_size) + salt;

    /* dynamic mem alloc
    unsigned char* M = (unsigned char*)malloc(8 + hLen + sLen);
    if (M == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }*/
    unsigned char M[72]; // buffer_m_prime? size hLen + sLen + padding (8)  
    
    unsigned char* curr = M;
    memcpy(curr, buffer_Padding1, 8);
    curr += 8;
    memcpy(curr, mHash, hLen);
    curr += hLen;
    memcpy(curr, salt, sLen);

    unsigned char H[32];
    hash(M, 72, H, 32); //octet string of length hLen

// Generate an octet string PS consisting of emLen - sLen - hLen
    size_t PSlen = encoded_message_size - sLen - hLen - 2; //256 - 32 - 32 - 2
    unsigned char* PS = (unsigned char*)malloc(PSlen);
    if (PS == NULL) return;
    memset(PS, 0, PSlen);


    size_t DBlen = encoded_message_size - hLen - 1;
    unsigned char DB[223]; // octet string length emLen-hLen - 1
    unsigned char* current_position = DB;

    memcpy(current_position, PS, PSlen);
    current_position += PSlen;

    //memcpy(current_position, 0x01, 1);
    *current_position = 0x01;
    current_position += 1;

    memcpy(current_position, salt, sLen);

    unsigned char dbMask[32];
    hash(H, encoded_message_size - hLen - 1, dbMask, 32);
    unsigned char* maskedDB[32];//maskedDB = DB xor dbMask;
    for (size_t i = 8; i < min(DBlen, hLen); ++i) {
        //maskedDB[i] = DB[i] ^ dbMask[i];
    }
    // Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
/* emBits   maximal bit length of the integer OS2IP (EM) (see Section4.2), at least 8hLen + 8sLen + 9*/
    /*size_t bits_to_zero = 8 * 256 - emBits;
    unsigned char mask = (unsigned char)(0xFF >> bits_to_zero);
    maskedDB[0] &= mask;*/
    //unsigned char* EM[/*maskedDB || H || 0xbc*/];
    current_position = encoded_message;

   // memcpy(current_position, maskedDB, sizeof(maskedDB));
    current_position += sizeof(maskedDB);
     
    memcpy(current_position, H, sizeof(H));
    current_position += sizeof(H);

    *current_position = 0xbc;
    current_position += 1;
}


int main(int argc, char** argv)

{

    int  encoded_message_size = 512;
    int message_size = strlen(message);

    unsigned char mHash[32];
    hash(message, message_size, mHash, sizeof(mHash));
    for (int i = 0; i < 32; i++) {
        printf("%x ", mHash[i]);
    }

    //return EM and memcpy outside, or memcpy to encoded_message inside of the function
    //prepare_em(SHA256, message, message_size, encoded_message, sizeof(encoded_message), encoded_message_size);
    /*
    for (unsigned char e : encoded_message) {
        printf(e + "\n");
    }*/
    unsigned char* testem;
    /*
mbedtls_rsa_context *ctx 

int (*f_rng)(void *, unsigned char *, size_t) - rng function pointer
void *p_rng              - context of the rng function
mbedtls_md_type_t md_alg - hash algorithm

unsigned int hashlen
const unsigned char *hash - buffer containing hash of message

int saltlen

unsigned char *sig - resulting signature buffer, 256 bytes
    */
   // rsa_rsassa_pss_sign_no_mode_check(
       /*mbedtls_rsa_context * ctx

        int (*f_rng)(void*, unsigned char*, size_t)
        void* p_rng
        mbedtls_md_type_t md_alg

        unsigned int hashlen
        */
    //    testem, 32, unsigned char* sig);

   // int i = OS2IP(EM); //Convert the encoded message EM to an integer message representative
   // s = RSASP1(K, m); // Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA private key K and 
    //the message representative
    //Convert the signature representative s to a signature S of length k octets(see Section 4.1) :

  // S = I2OSP(s, k).
}