/*
 * Fuzzing harness for OpenSSL library - Advanced RSA Operations
 * Targets: RSA asymmetric cryptography operations with advanced padding schemes
 * Coverage gaps identified: PKCS#1, OAEP, PSS padding, EVP_PKEY operations for RSA,
 * RSA key generation, encryption/decryption with different padding modes,
 * RSA signing/verification, multi-prime RSA, RSA blinding
 * Semantic diversity from harness_000.cpp (basic RSA) and harness_001.cpp (DTLS)
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough for basic RSA operations
    if (size < 64) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                       OPENSSL_INIT_ADD_ALL_CIPHERS | 
                       OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    ERR_clear_error();
    
    // Consume operation type to determine testing path
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 12;
    
    switch (operation) {
        case 0: {
            /* Test RSA with different padding modes */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    // Consume RSA key size from fuzzer input
                    int bits = fdp.ConsumeIntegralInRange<int>(256, 2048);
                    // Consume exponent from fuzzer input (common values: 3, 17, 65537)
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    
                    // Consume data to encrypt
                    size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, RSA_size(rsa) - 42);
                    std::vector<uint8_t> plaintext = fdp.ConsumeBytes<uint8_t>(data_size);
                    
                    if (!plaintext.empty()) {
                        unsigned char encrypted[4096];
                        unsigned char decrypted[4096];
                        int encrypted_len = 0, decrypted_len = 0;
                        
                        // Test different padding modes
                        uint8_t padding_mode = fdp.ConsumeIntegral<uint8_t>() % 4;
                        int padding = RSA_PKCS1_PADDING;
                        
                        switch (padding_mode) {
                            case 0: padding = RSA_PKCS1_PADDING; break;
                            case 1: padding = RSA_PKCS1_OAEP_PADDING; break;
                            case 2: padding = RSA_X931_PADDING; break;
                            case 3: padding = RSA_NO_PADDING; break;
                        }
                        
                        // Public encrypt / private decrypt
                        encrypted_len = RSA_public_encrypt(plaintext.size(), plaintext.data(),
                                                          encrypted, rsa, padding);
                        if (encrypted_len > 0) {
                            decrypted_len = RSA_private_decrypt(encrypted_len, encrypted,
                                                               decrypted, rsa, padding);
                        }
                        
                        // Also test private encrypt / public decrypt
                        if (plaintext.size() > 0) {
                            encrypted_len = RSA_private_encrypt(plaintext.size(), plaintext.data(),
                                                              encrypted, rsa, padding);
                            if (encrypted_len > 0) {
                                decrypted_len = RSA_public_decrypt(encrypted_len, encrypted,
                                                                 decrypted, rsa, padding);
                            }
                        }
                    }
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 1: {
            /* Test EVP_PKEY RSA operations with PSS padding */
            EVP_PKEY* pkey = NULL;
            EVP_PKEY_CTX* ctx = NULL;
            
            // Generate RSA key using EVP_PKEY
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0) {
                // Consume key size from fuzzer input
                int bits = fdp.ConsumeIntegralInRange<int>(256, 2048);
                if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) > 0) {
                    EVP_PKEY_keygen(ctx, &pkey);
                }
                EVP_PKEY_CTX_free(ctx);
            }
            
            if (pkey != NULL) {
                // Get RSA object from EVP_PKEY
                RSA* rsa = EVP_PKEY_get1_RSA(pkey);
                if (rsa != NULL) {
                    // Consume data for signing
                    size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, 256);
                    std::vector<uint8_t> data_to_sign = fdp.ConsumeBytes<uint8_t>(data_size);
                    
                    if (!data_to_sign.empty()) {
                        // Test RSA signing and verification
                        unsigned char signature[4096];
                        unsigned int sig_len = sizeof(signature);
                        
                        // Sign with different hash algorithms
                        uint8_t hash_type = fdp.ConsumeIntegral<uint8_t>() % 3;
                        int type = NID_sha256;
                        switch (hash_type) {
                            case 0: type = NID_sha1; break;
                            case 1: type = NID_sha256; break;
                            case 2: type = NID_sha512; break;
                        }
                        
                        if (RSA_sign(type, data_to_sign.data(), data_to_sign.size(),
                                    signature, &sig_len, rsa) > 0) {
                            // Verify the signature
                            RSA_verify(type, data_to_sign.data(), data_to_sign.size(),
                                      signature, sig_len, rsa);
                        }
                        
                        // Test ASN1 OCTET STRING signing
                        if (RSA_sign_ASN1_OCTET_STRING(0, data_to_sign.data(), data_to_sign.size(),
                                                      signature, &sig_len, rsa) > 0) {
                            RSA_verify_ASN1_OCTET_STRING(0, data_to_sign.data(), data_to_sign.size(),
                                                        signature, sig_len, rsa);
                        }
                    }
                    
                    RSA_free(rsa);
                }
                EVP_PKEY_free(pkey);
            }
            break;
        }
        
        case 2: {
            /* Test multi-prime RSA key generation */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    // Consume parameters from fuzzer input
                    int bits = fdp.ConsumeIntegralInRange<int>(512, 2048);
                    int primes = fdp.ConsumeIntegralInRange<int>(2, 5);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    // Generate multi-prime RSA key
                    RSA_generate_multi_prime_key(rsa, bits, primes, e, NULL);
                    
                    // Test encryption/decryption with multi-prime key
                    size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, RSA_size(rsa) - 42);
                    std::vector<uint8_t> plaintext = fdp.ConsumeBytes<uint8_t>(data_size);
                    
                    if (!plaintext.empty()) {
                        unsigned char encrypted[4096];
                        unsigned char decrypted[4096];
                        
                        int encrypted_len = RSA_public_encrypt(plaintext.size(), plaintext.data(),
                                                              encrypted, rsa, RSA_PKCS1_PADDING);
                        if (encrypted_len > 0) {
                            RSA_private_decrypt(encrypted_len, encrypted,
                                               decrypted, rsa, RSA_PKCS1_PADDING);
                        }
                    }
                    
                    // Test RSA key checking
                    RSA_check_key(rsa);
                    RSA_check_key_ex(rsa, NULL);
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 3: {
            /* Test RSA blinding operations */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    int bits = fdp.ConsumeIntegralInRange<int>(256, 1024);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    RSA_generate_key_ex(rsa, bits, e, NULL);
                    
                    // Enable blinding
                    BN_CTX* bn_ctx = BN_CTX_new();
                    if (bn_ctx != NULL) {
                        RSA_blinding_on(rsa, bn_ctx);
                        
                        // Test encryption with blinding enabled
                        size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, RSA_size(rsa) - 42);
                        std::vector<uint8_t> plaintext = fdp.ConsumeBytes<uint8_t>(data_size);
                        
                        if (!plaintext.empty()) {
                            unsigned char encrypted[2048];
                            unsigned char decrypted[2048];
                            
                            RSA_public_encrypt(plaintext.size(), plaintext.data(),
                                             encrypted, rsa, RSA_PKCS1_PADDING);
                            RSA_private_decrypt(RSA_size(rsa), encrypted,
                                               decrypted, rsa, RSA_PKCS1_PADDING);
                        }
                        
                        // Setup blinding explicitly
                        BN_BLINDING* blinding = RSA_setup_blinding(rsa, bn_ctx);
                        if (blinding != NULL) {
                            // Blinding object created, can be used
                        }
                        
                        RSA_blinding_off(rsa);
                        BN_CTX_free(bn_ctx);
                    }
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 4: {
            /* Test RSA key import/export and component manipulation */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    int bits = fdp.ConsumeIntegralInRange<int>(256, 1024);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    RSA_generate_key_ex(rsa, bits, e, NULL);
                    
                    // Get key components
                    const BIGNUM* n = NULL;
                    const BIGNUM* e_get = NULL;
                    const BIGNUM* d = NULL;
                    const BIGNUM* p = NULL;
                    const BIGNUM* q = NULL;
                    const BIGNUM* dmp1 = NULL;
                    const BIGNUM* dmq1 = NULL;
                    const BIGNUM* iqmp = NULL;
                    
                    RSA_get0_key(rsa, &n, &e_get, &d);
                    RSA_get0_factors(rsa, &p, &q);
                    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
                    
                    // Test individual getters
                    RSA_get0_n(rsa);
                    RSA_get0_e(rsa);
                    RSA_get0_d(rsa);
                    RSA_get0_p(rsa);
                    RSA_get0_q(rsa);
                    RSA_get0_dmp1(rsa);
                    RSA_get0_dmq1(rsa);
                    RSA_get0_iqmp(rsa);
                    
                    // Test RSA flags operations
                    int flags = fdp.ConsumeIntegral<int>();
                    RSA_set_flags(rsa, flags);
                    RSA_test_flags(rsa, flags);
                    RSA_clear_flags(rsa, flags);
                    
                    // Test RSA version
                    RSA_get_version(rsa);
                    
                    // Test RSA security bits
                    RSA_security_bits(rsa);
                    RSA_bits(rsa);
                    RSA_size(rsa);
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 5: {
            /* Test RSA with X.931 padding and key generation */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    // Consume parameters for X931 key generation
                    int bits = fdp.ConsumeIntegralInRange<int>(512, 1024);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    
                    // Generate X931 key
                    RSA_X931_generate_key_ex(rsa, bits, e, NULL);
                    
                    // Test encryption with X931 padding
                    size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, RSA_size(rsa) - 42);
                    std::vector<uint8_t> plaintext = fdp.ConsumeBytes<uint8_t>(data_size);
                    
                    if (!plaintext.empty()) {
                        unsigned char encrypted[2048];
                        unsigned char decrypted[2048];
                        
                        RSA_public_encrypt(plaintext.size(), plaintext.data(),
                                         encrypted, rsa, RSA_X931_PADDING);
                        if (RSA_size(rsa) > 0) {
                            RSA_private_decrypt(RSA_size(rsa), encrypted,
                                               decrypted, rsa, RSA_X931_PADDING);
                        }
                    }
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 6: {
            /* Test RSA PSS parameters */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    int bits = fdp.ConsumeIntegralInRange<int>(256, 1024);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    RSA_generate_key_ex(rsa, bits, e, NULL);
                    
                    // Get PSS parameters
                    const RSA_PSS_PARAMS* pss_params = RSA_get0_pss_params(rsa);
                    // pss_params may be NULL for regular RSA keys
                    
                    // Test RSA with PSS padding (EVP_PKEY level)
                    EVP_PKEY* pkey = EVP_PKEY_new();
                    if (pkey != NULL) {
                        EVP_PKEY_assign_RSA(pkey, rsa);
                        
                        // Create signing context with PSS
                        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
                        if (ctx != NULL) {
                            size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, 128);
                            std::vector<uint8_t> data_to_sign = fdp.ConsumeBytes<uint8_t>(data_size);
                            
                            if (!data_to_sign.empty()) {
                                // Initialize signing with PSS
                                if (EVP_PKEY_sign_init(ctx) > 0) {
                                    // Set PSS padding
                                    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
                                    
                                    unsigned char signature[4096];
                                    size_t sig_len = sizeof(signature);
                                    
                                    // Try to sign (may fail if PSS parameters not set)
                                    EVP_PKEY_sign(ctx, signature, &sig_len, 
                                                 data_to_sign.data(), data_to_sign.size());
                                }
                            }
                            
                            EVP_PKEY_CTX_free(ctx);
                        }
                        
                        // Don't free rsa - it's owned by pkey now
                        EVP_PKEY_free(pkey);
                    } else {
                        RSA_free(rsa);
                    }
                    
                    BN_free(e);
                }
            }
            break;
        }
        
        case 7: {
            /* Test RSA method operations */
            const RSA_METHOD* default_meth = RSA_get_default_method();
            RSA_set_default_method(default_meth);
            
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                // Test method operations
                const RSA_METHOD* meth = RSA_get_method(rsa);
                RSA_get_default_method();
                RSA_null_method();
                RSA_PKCS1_OpenSSL();
                
                // Test method flags and names
                if (meth != NULL) {
                    RSA_meth_get_flags(meth);
                    RSA_meth_get0_name(meth);
                }
                
                RSA_free(rsa);
            }
            break;
        }
        
        case 8: {
            /* Test RSA reference counting and duplicate */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    int bits = fdp.ConsumeIntegralInRange<int>(256, 1024);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    RSA_generate_key_ex(rsa, bits, e, NULL);
                    
                    // Test reference counting
                    RSA_up_ref(rsa);
                    
                    // Test RSA flags
                    RSA_flags(rsa);
                    
                    // Create another RSA and test set_method
                    RSA* rsa2 = RSA_new();
                    if (rsa2 != NULL) {
                        const RSA_METHOD* meth = RSA_get_method(rsa);
                        RSA_set_method(rsa2, meth);
                        RSA_free(rsa2);
                    }
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 9: {
            /* Test RSA PEM and BIO operations */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                BIGNUM* e = BN_new();
                if (e != NULL) {
                    int bits = fdp.ConsumeIntegralInRange<int>(256, 1024);
                    // Consume exponent from fuzzer input
                    unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                    BN_set_word(e, exponent);
                    RSA_generate_key_ex(rsa, bits, e, NULL);
                    
                    // Test BIO printing
                    BIO* bio = BIO_new(BIO_s_mem());
                    if (bio != NULL) {
                        RSA_print(bio, rsa, 0);
                        BIO_free(bio);
                    }
                    
                    BN_free(e);
                }
                RSA_free(rsa);
            }
            break;
        }
        
        case 10: {
            /* Test RSA with custom app data */
            RSA* rsa = RSA_new();
            if (rsa != NULL) {
                // Set and get app data
                int app_data = 42;
                RSA_set_app_data(rsa, &app_data);
                RSA_get_app_data(rsa);
                
                RSA_free(rsa);
            }
            break;
        }
        
        case 11: {
            /* Test RSA with various key sizes and exponents */
            for (int i = 0; i < 3 && fdp.remaining_bytes() > 16; i++) {
                RSA* rsa = RSA_new();
                if (rsa != NULL) {
                    BIGNUM* e = BN_new();
                    if (e != NULL) {
                        // Consume different exponent values
                        unsigned long exponent = fdp.ConsumeIntegralInRange<unsigned long>(3, 65537);
                        BN_set_word(e, exponent);
                        
                        // Consume different key sizes
                        int bits = fdp.ConsumeIntegralInRange<int>(128, 2048);
                        
                        // Try to generate key (may fail for very small sizes)
                        RSA_generate_key_ex(rsa, bits, e, NULL);
                        
                        // Test basic operations if key generation succeeded
                        if (RSA_size(rsa) > 0) {
                            size_t data_size = fdp.ConsumeIntegralInRange<size_t>(1, RSA_size(rsa) - 42);
                            if (data_size > 0 && fdp.remaining_bytes() >= data_size) {
                                std::vector<uint8_t> plaintext = fdp.ConsumeBytes<uint8_t>(data_size);
                                if (!plaintext.empty()) {
                                    unsigned char encrypted[4096];
                                    RSA_public_encrypt(plaintext.size(), plaintext.data(),
                                                     encrypted, rsa, RSA_PKCS1_PADDING);
                                }
                            }
                        }
                        
                        BN_free(e);
                    }
                    RSA_free(rsa);
                }
            }
            break;
        }
    }
    
    // Clear any accumulated errors
    ERR_clear_error();
    
    return 0;
}
