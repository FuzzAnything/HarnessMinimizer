/*
 * OpenSSL 3.0 Provider API and TLS 1.3 Advanced Functions Fuzzing Harness
 * Targets completely uncovered high-complexity modules:
 * - Provider API (OpenSSL 3.0+): OSSL_PROVIDER, OSSL_LIB_CTX
 * - TLS 1.3 Specific Functions: SSL_CTX_set_ciphersuites, SSL_set_psk_use_session_callback
 * - OCSP (Online Certificate Status Protocol): OCSP_basic_verify
 * - CMS/PKCS#7: CMS_verify
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/cms.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 64) {
        return 0;  // Insufficient input for meaningful testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL with provider support
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                       OPENSSL_INIT_ADD_ALL_CIPHERS | 
                       OPENSSL_INIT_ADD_ALL_DIGESTS |
                       OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    
    // Consume operation type to determine which APIs to test
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    switch (operation) {
        case 0: {
            // Test Provider API: OSSL_LIB_CTX_new and OSSL_PROVIDER_load
            OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
            if (libctx != NULL) {
                // Try loading different providers based on fuzzer input
                std::string provider_name;
                uint8_t provider_choice = fdp.ConsumeIntegral<uint8_t>() % 4;
                
                if (provider_choice == 0) {
                    provider_name = "default";
                } else if (provider_choice == 1) {
                    provider_name = "base";
                } else if (provider_choice == 2) {
                    provider_name = "null";
                } else {
                    // Consume provider name from fuzzer input
                    provider_name = fdp.ConsumeRandomLengthString(32);
                }
                
                OSSL_PROVIDER* provider = OSSL_PROVIDER_load(libctx, provider_name.c_str());
                if (provider != NULL) {
                    // Test getting provider properties
                    const char* name = OSSL_PROVIDER_get0_name(provider);
                    
                    // Try to enable FIPS mode if available
                    int fips_enabled = EVP_default_properties_enable_fips(libctx, 1);
                    
                    // Test provider parameter retrieval
                    const OSSL_PARAM* params = OSSL_PROVIDER_gettable_params(provider);
                    
                    // Unload provider
                    OSSL_PROVIDER_unload(provider);
                }
                
                // Free library context
                OSSL_LIB_CTX_free(libctx);
            }
            break;
        }
        
        case 1: {
            // Test TLS 1.3 specific functions
            SSL_CTX* ctx = SSL_CTX_new(TLS_method());
            if (ctx != NULL) {
                // Set TLS 1.3 as minimum version
                SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
                SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
                
                // Set TLS 1.3 ciphersuites from fuzzer input
                if (fdp.remaining_bytes() > 10) {
                    std::string ciphersuites = fdp.ConsumeRandomLengthString(256);
                    SSL_CTX_set_ciphersuites(ctx, ciphersuites.c_str());
                }
                
                // Create SSL object
                SSL* ssl = SSL_new(ctx);
                if (ssl != NULL) {
                    // Set PSK use session callback (TLS 1.3 feature)
                    SSL_set_psk_use_session_callback(ssl, NULL);
                    
                    // Create BIOs for testing
                    BIO* rbio = BIO_new(BIO_s_mem());
                    BIO* wbio = BIO_new(BIO_s_mem());
                    if (rbio != NULL && wbio != NULL) {
                        SSL_set_bio(ssl, rbio, wbio);
                        
                        // Set connection state
                        if (fdp.ConsumeBool()) {
                            SSL_set_connect_state(ssl);
                        } else {
                            SSL_set_accept_state(ssl);
                        }
                        
                        // Try handshake
                        SSL_do_handshake(ssl);
                        
                        // Clean up
                        SSL_shutdown(ssl);
                    }
                    
                    SSL_free(ssl);
                }
                
                SSL_CTX_free(ctx);
            }
            break;
        }
        
        case 2: {
            // Test OCSP basic verification
            // Create a basic OCSP response structure for testing
            OCSP_BASICRESP* br = OCSP_BASICRESP_new();
            if (br != NULL) {
                // Create test certificates
                X509* cert = X509_new();
                X509* issuer = X509_new();
                EVP_PKEY* pkey = EVP_PKEY_new();
                
                if (cert != NULL && issuer != NULL && pkey != NULL) {
                    // Initialize certificates with some basic data
                    ASN1_INTEGER* serial = ASN1_INTEGER_new();
                    if (serial != NULL) {
                        ASN1_INTEGER_set(serial, 12345);
                        X509_set_serialNumber(cert, serial);
                        ASN1_INTEGER_free(serial);
                    }
                    
                    // Set issuer name
                    X509_NAME* name = X509_NAME_new();
                    if (name != NULL) {
                        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                                                  (const unsigned char*)"Test CA", -1, -1, 0);
                        X509_set_issuer_name(cert, name);
                        X509_set_subject_name(issuer, name);
                        X509_NAME_free(name);
                    }
                    
                    // Set public key
                    RSA* rsa = RSA_new();
                    if (rsa != NULL) {
                        BIGNUM* e = BN_new();
                        if (e != NULL) {
                            BN_set_word(e, 65537);
                            RSA_generate_key_ex(rsa, 512, e, NULL);
                            EVP_PKEY_assign_RSA(pkey, rsa);
                            X509_set_pubkey(cert, pkey);
                            X509_set_pubkey(issuer, pkey);
                            BN_free(e);
                        }
                    }
                    
                    // Set certificate validity
                    ASN1_TIME* not_before = ASN1_TIME_new();
                    ASN1_TIME* not_after = ASN1_TIME_new();
                    if (not_before != NULL && not_after != NULL) {
                        X509_gmtime_adj(not_before, -86400);  // Yesterday
                        X509_gmtime_adj(not_after, 86400);    // Tomorrow
                        X509_set1_notBefore(cert, not_before);
                        X509_set1_notAfter(cert, not_after);
                        ASN1_TIME_free(not_before);
                        ASN1_TIME_free(not_after);
                    }
                    
                    // Create OCSP request
                    OCSP_CERTID* id = OCSP_cert_to_id(NULL, cert, issuer);
                    if (id != NULL) {
                        // Add response for the certificate
                        OCSP_basic_add1_status(br, id, V_OCSP_CERTSTATUS_GOOD, 0, NULL, 
                                              not_before, not_after);
                        
                        // Try verification (will likely fail due to missing signatures)
                        STACK_OF(X509)* certs = sk_X509_new_null();
                        if (certs != NULL) {
                            sk_X509_push(certs, issuer);
                            
                            // Get verification flags from fuzzer input
                            unsigned long flags = 0;
                            if (fdp.ConsumeBool()) flags |= OCSP_NOCHECKS;
                            if (fdp.ConsumeBool()) flags |= OCSP_NOSIGS;
                            
                            OCSP_basic_verify(br, certs, NULL, flags);
                            
                            sk_X509_free(certs);
                        }
                        
                        OCSP_CERTID_free(id);
                    }
                }
                
                if (cert != NULL) X509_free(cert);
                if (issuer != NULL) X509_free(issuer);
                if (pkey != NULL) EVP_PKEY_free(pkey);
                
                OCSP_BASICRESP_free(br);
            }
            break;
        }
        
        case 3: {
            // Test CMS verification
            // Create a simple CMS message for testing
            if (fdp.remaining_bytes() > 100) {
                size_t cms_data_len = fdp.ConsumeIntegralInRange<size_t>(100, fdp.remaining_bytes());
                std::vector<uint8_t> cms_data = fdp.ConsumeBytes<uint8_t>(cms_data_len);
                
                // Try to parse as CMS
                BIO* cms_bio = BIO_new_mem_buf(cms_data.data(), cms_data.size());
                if (cms_bio != NULL) {
                    CMS_ContentInfo* cms = d2i_CMS_bio(cms_bio, NULL);
                    if (cms != NULL) {
                        // Create test certificates for verification
                        X509* cert = X509_new();
                        X509* issuer = X509_new();
                        EVP_PKEY* pkey = EVP_PKEY_new();
                        STACK_OF(X509)* certs = NULL;
                        
                        if (cert != NULL && issuer != NULL && pkey != NULL) {
                            // Initialize certificates
                            ASN1_INTEGER* serial = ASN1_INTEGER_new();
                            if (serial != NULL) {
                                ASN1_INTEGER_set(serial, 67890);
                                X509_set_serialNumber(cert, serial);
                                ASN1_INTEGER_free(serial);
                            }
                            
                            // Set names
                            X509_NAME* name = X509_NAME_new();
                            if (name != NULL) {
                                X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                                                          (const unsigned char*)"Test Signer", -1, -1, 0);
                                X509_set_subject_name(cert, name);
                                X509_set_issuer_name(issuer, name);
                                X509_NAME_free(name);
                            }
                            
                            // Set public key
                            RSA* rsa = RSA_new();
                            if (rsa != NULL) {
                                BIGNUM* e = BN_new();
                                if (e != NULL) {
                                    BN_set_word(e, 65537);
                                    RSA_generate_key_ex(rsa, 512, e, NULL);
                                    EVP_PKEY_assign_RSA(pkey, rsa);
                                    X509_set_pubkey(cert, pkey);
                                    X509_set_pubkey(issuer, pkey);
                                    BN_free(e);
                                }
                            }
                            
                            // Create certificate stack
                            certs = sk_X509_new_null();
                            if (certs != NULL) {
                                sk_X509_push(certs, cert);
                                sk_X509_push(certs, issuer);
                                
                                // Get store for verification
                                X509_STORE* store = X509_STORE_new();
                                if (store != NULL) {
                                    X509_STORE_add_cert(store, issuer);
                                    
                                    // Get verification flags from fuzzer input
                                    unsigned int flags = 0;
                                    if (fdp.ConsumeBool()) flags |= CMS_NO_SIGNER_CERT_VERIFY;
                                    if (fdp.ConsumeBool()) flags |= CMS_NOCERTS;
                                    
                                    // Try CMS verification
                                    CMS_verify(cms, certs, store, NULL, NULL, flags);
                                    
                                    X509_STORE_free(store);
                                }
                                
                                sk_X509_free(certs);
                            }
                        }
                        
                        if (cert != NULL) X509_free(cert);
                        if (issuer != NULL) X509_free(issuer);
                        if (pkey != NULL) EVP_PKEY_free(pkey);
                        
                        CMS_ContentInfo_free(cms);
                    }
                    BIO_free(cms_bio);
                }
            }
            break;
        }
    }
    
    // Clean up any remaining errors
    ERR_clear_error();
    
    return 0;
}
