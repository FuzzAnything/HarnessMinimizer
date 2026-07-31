/*
 * Fuzzing harness for OpenSSL EVP_PKEY_CTX DH/X9.42 operations
 * Targets: Diffie-Hellman parameter generation and RFC5114 configuration
 * Specifically targets uncovered APIs: EVP_PKEY_CTX_get1_id_len (442 undiscovered branches),
 *   EVP_PKEY_CTX_set_dhx_rfc5114 (442 undiscovered branches), EVP_PKEY_CTX_new_id (init),
 *   EVP_PKEY_paramgen_init (setup), EVP_PKEY_paramgen (parameter generation), 
 *   EVP_PKEY_CTX_free (cleanup)
 * Additional related APIs: EVP_PKEY_CTX_set_dh_paramgen_type, 
 *   EVP_PKEY_CTX_set_dh_paramgen_generator, EVP_PKEY_CTX_set_dh_rfc5114
 * Focus: DH/X9.42 parameter generation security with RFC5114 standards
 * Differentiation: harness_000 targets core crypto, harness_001 targets SSL/TLS/CMS,
 *   harness_002 targets provider architecture, harness_003 targets CMP protocol,
 *   this harness targets DH parameter generation security
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) {
        return 0; // Need minimum data for meaningful DH operations
    }

    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL library for DH operations
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                       OPENSSL_INIT_ADD_ALL_CIPHERS | 
                       OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    ERR_clear_error();

    // Step 1: Consume fixed-size data for DH parameter generation configuration
    uint8_t dh_type = fdp.ConsumeIntegral<uint8_t>() % 2; // 0 = DH, 1 = DHX
    uint8_t rfc5114_param = fdp.ConsumeIntegral<uint8_t>() % 4; // RFC5114 parameter set 1-3
    uint8_t paramgen_type = fdp.ConsumeIntegral<uint8_t>() % 3; // Parameter generation type
    uint8_t generator = fdp.ConsumeIntegral<uint8_t>() % 5; // Generator value
    bool use_rfc5114 = fdp.ConsumeBool();
    bool query_id_len = fdp.ConsumeBool();
    
    // Consume additional configuration parameters
    int prime_len = fdp.ConsumeIntegralInRange<int>(512, 4096);
    int subprime_len = fdp.ConsumeIntegralInRange<int>(160, 512);
    
    // Determine DH type (EVP_PKEY_DH or EVP_PKEY_DHX)
    int dh_nid = (dh_type == 0) ? EVP_PKEY_DH : EVP_PKEY_DHX;
    
    // Step 2: Create context for X9.42 DH (EVP_PKEY_CTX_new_id)
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(dh_nid, NULL);
    if (ctx == NULL) {
        ERR_clear_error();
        return 0;
    }
    
    // Step 3: Initialize parameter generation (EVP_PKEY_paramgen_init)
    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        ERR_clear_error();
        return 0;
    }
    
    // Step 4: Set RFC5114 parameters (EVP_PKEY_CTX_set_dhx_rfc5114)
    if (dh_nid == EVP_PKEY_DHX && use_rfc5114) {
        // RFC5114 defines three parameter sets: 1 (1024-bit), 2 (2048-bit), 3 (2048-bit)
        int rfc5114_value = (rfc5114_param % 3) + 1;
        EVP_PKEY_CTX_set_dhx_rfc5114(ctx, rfc5114_value);
    }
    
    // Step 5: Query identifier length (EVP_PKEY_CTX_get1_id_len)
    size_t id_len = 0;
    if (query_id_len) {
        EVP_PKEY_CTX_get1_id_len(ctx, &id_len);
    }
    
    // Step 6: Set DH parameter generation controls
    
    // Set parameter generation type (EVP_PKEY_CTX_set_dh_paramgen_type)
    // Types: 0 = DH_PARAMGEN_TYPE_GENERATOR, 1 = DH_PARAMGEN_TYPE_FIPS_186_2, 
    //        2 = DH_PARAMGEN_TYPE_FIPS_186_4
    EVP_PKEY_CTX_set_dh_paramgen_type(ctx, paramgen_type);
    
    // Set generator (EVP_PKEY_CTX_set_dh_paramgen_generator)
    // Common generators: 2, 3, 5 (small primes)
    int gen_value = (generator % 3 == 0) ? 2 : ((generator % 3 == 1) ? 3 : 5);
    EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen_value);
    
    // Set prime length
    EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, prime_len);
    
    // Set subprime length if applicable
    if (subprime_len > 0) {
        EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, subprime_len);
    }
    
    // Step 7: Generate DH parameters (EVP_PKEY_paramgen)
    EVP_PKEY* params = NULL;
    if (EVP_PKEY_paramgen(ctx, &params) > 0 && params != NULL) {
        // Parameter generation succeeded, we can perform additional operations
        
        // Optionally set RFC5114 parameters for DH (not DHX)
        if (dh_nid == EVP_PKEY_DH && use_rfc5114) {
            int rfc5114_value = (rfc5114_param % 3) + 1;
            EVP_PKEY_CTX_set_dh_rfc5114(ctx, rfc5114_value);
        }
        
        // Test getting the generated parameters
        const DH* dh_params = EVP_PKEY_get0_DH(params);
        if (dh_params != NULL) {
            // Extract parameters from generated DH
            const BIGNUM* p = NULL;
            const BIGNUM* q = NULL;
            const BIGNUM* g = NULL;
            
            DH_get0_pqg(dh_params, &p, &q, &g);
            
            // Perform basic DH operations if we have valid parameters
            if (p != NULL && g != NULL) {
                // Generate a key pair using the parameters
                EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params, NULL);
                if (key_ctx != NULL) {
                    if (EVP_PKEY_keygen_init(key_ctx) > 0) {
                        EVP_PKEY* key = NULL;
                        if (EVP_PKEY_keygen(key_ctx, &key) > 0 && key != NULL) {
                            // Key generation succeeded
                            EVP_PKEY_free(key);
                        }
                    }
                    EVP_PKEY_CTX_free(key_ctx);
                }
            }
        }
        
        EVP_PKEY_free(params);
    }
    
    // Step 8: Cleanup (EVP_PKEY_CTX_free)
    EVP_PKEY_CTX_free(ctx);
    
    // Clear any remaining errors
    ERR_clear_error();
    
    return 0;
}
