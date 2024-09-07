/*
#include "psa/crypto.h"
void sign_a_message_using_rsa(const uint8_t* key, size_t key_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t hash[32] = { 0x50, 0xd8, 0x58, 0xe0, 0x98, 0x5e, 0xcc, 0x7f,
                        0x60, 0x41, 0x8a, 0xaf, 0x0c, 0xc5, 0xab, 0x58,
                        0x7f, 0x42, 0xc2, 0x57, 0x0a, 0x88, 0x40, 0x95,
                        0xa9, 0xe8, 0xcc, 0xac, 0xd0, 0xf6, 0x54, 0x5c };
    uint8_t signature[PSA_SIGNATURE_MAX_SIZE] = { 0 };
    size_t signature_length;
    psa_key_id_t key_id;

    printf("Sign a message...\t");
    fflush(stdout);

    // Initialize PSA Crypto 
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    // Set key attributes 
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, 1024);

    // Import the key 
    status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        printf("Failed to import key\n");
        return;
    }

    // Sign message using the key 
    status = psa_sign_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
        hash, sizeof(hash),
        signature, sizeof(signature),
        &signature_length);
    if (status != PSA_SUCCESS) {
        printf("Failed to sign\n");
        return;
    }

    printf("Signed a message\n");

    // Free the attributes 
    psa_reset_key_attributes(&attributes);

    // Destroy the key 
    psa_destroy_key(key_id);

    mbedtls_psa_crypto_free();
}*/