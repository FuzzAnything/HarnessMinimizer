/*
 * Fuzzing harness for OpenSSL OCSP (Online Certificate Status Protocol) functions
 * Targets: Complete OCSP request/response lifecycle with near-zero coverage (0.5%)
 * Coverage goal: Uncover entire ocsp/ directory (117 functions across 9 files)
 * Semantic differentiation: OCSP protocol testing (vs. crypto basics in harness_000.cpp and SSL/TLS in harness_001.cpp)
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 64) {
        return 0; // Need minimum input for meaningful OCSP testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                       OPENSSL_INIT_ADD_ALL_CIPHERS | 
                       OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    ERR_clear_error();
    
    // Determine which OCSP operation to test based on first byte
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Consume parameters that will be used across all operations
    int nid = fdp.ConsumeIntegralInRange<int>(1, 1000); // Extension NID
    int status = fdp.ConsumeIntegralInRange<int>(0, 5); // OCSP response status
    int cert_status = fdp.ConsumeIntegralInRange<int>(0, 2); // Certificate status
    
    // Consume certificate data from fuzzer input
    size_t issuer_name_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
    size_t subject_name_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
    std::string issuer_name_str = fdp.ConsumeBytesAsString(issuer_name_len);
    std::string subject_name_str = fdp.ConsumeBytesAsString(subject_name_len);
    long serial_number = fdp.ConsumeIntegral<long>();
    // Create synthetic certificates for testing using fuzzed data
    X509 *issuer_cert = X509_new();
    X509 *subject_cert = X509_new();
    
    if (issuer_cert == NULL || subject_cert == NULL) {
        if (issuer_cert) X509_free(issuer_cert);
        if (subject_cert) X509_free(subject_cert);
        return 0;
    }
    
    // Set some basic fields on the synthetic certificates using fuzzed input
    X509_NAME *issuer_name = X509_NAME_new();
    X509_NAME *subject_name = X509_NAME_new();
    
    if (issuer_name && subject_name) {
        // Add entries to the names using fuzzed input
        if (!issuer_name_str.empty()) {
            X509_NAME_add_entry_by_txt(issuer_name, "CN", MBSTRING_ASC, 
                                      (const unsigned char *)issuer_name_str.c_str(), -1, -1, 0);
        }
        if (!subject_name_str.empty()) {
            X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
                                      (const unsigned char *)subject_name_str.c_str(), -1, -1, 0);
        }
        
        X509_set_issuer_name(issuer_cert, issuer_name);
        X509_set_subject_name(subject_cert, subject_name);
        X509_set_subject_name(issuer_cert, issuer_name);
        
        // Set serial numbers using fuzzed input
        ASN1_INTEGER *serial = ASN1_INTEGER_new();
        if (serial) {
            ASN1_INTEGER_set(serial, serial_number);
            X509_set_serialNumber(subject_cert, serial);
            ASN1_INTEGER_free(serial);
        }
    }
    
    switch (operation) {
        case 0: {
            // Test OCSP request creation and printing
            OCSP_REQUEST *req = OCSP_REQUEST_new();
            if (req == NULL) {
                break;
            }
            
            // Create certificate ID using OCSP_cert_to_id
            const EVP_MD *dgst = EVP_sha256();
            OCSP_CERTID *cert_id = OCSP_cert_to_id(dgst, subject_cert, issuer_cert);
            if (cert_id) {
                // Add certificate ID to request
                OCSP_request_add0_id(req, cert_id);
                
                // Create memory BIO for printing
                BIO *bio = BIO_new(BIO_s_mem());
                if (bio) {
                    // Test OCSP_REQUEST_print
                    unsigned long flags = fdp.ConsumeIntegral<unsigned long>();
                    OCSP_REQUEST_print(bio, req, flags);
                    BIO_free(bio);
                }
                
                // Test OCSP_REQUEST_get1_ext_d2i with various NIDs
                int crit = 0;
                int idx = -1;
                void *ext_data = OCSP_REQUEST_get1_ext_d2i(req, nid, &crit, &idx);
                if (ext_data) {
                    // Extension data retrieved, free it
                    // Note: Actual type depends on NID, we just free generic pointer
                    // In real usage, would cast to appropriate type
                    ASN1_TYPE_free((ASN1_TYPE *)ext_data);
                }
            }
            
            OCSP_REQUEST_free(req);
            break;
        }
        
        case 1: {
            // Test OCSP response creation and lifecycle
            OCSP_REQUEST *req = OCSP_REQUEST_new();
            OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
            
            if (req && bs) {
                // Create certificate ID
                const EVP_MD *dgst = EVP_sha1(); // Use SHA1 for variety
                OCSP_CERTID *cert_id = OCSP_cert_to_id(dgst, subject_cert, issuer_cert);
                
                if (cert_id) {
                    // Add certificate ID to request
                    OCSP_request_add0_id(req, cert_id);
                    
                    // Create times for response
                    ASN1_TIME *thisupd = ASN1_TIME_new();
                    ASN1_TIME *nextupd = ASN1_TIME_new();
                    
                    if (thisupd && nextupd) {
                        time_t now = time(NULL);
                        ASN1_TIME_set(thisupd, now);
                        ASN1_TIME_set(nextupd, now + 3600); // 1 hour later
                        
                        // Add status to basic response
                        OCSP_basic_add1_status(bs, cert_id, cert_status, 
                                            0, NULL, thisupd, nextupd);
                        
                        // Create OCSP response
                        OCSP_RESPONSE *resp = OCSP_response_create(status, bs);
                        if (resp) {
                            // Test OCSP_RESPONSE_print
                            BIO *bio = BIO_new(BIO_s_mem());
                            if (bio) {
                                unsigned long flags = fdp.ConsumeIntegral<unsigned long>();
                                OCSP_RESPONSE_print(bio, resp, flags);
                                BIO_free(bio);
                            }
                            
                            OCSP_RESPONSE_free(resp);
                        }
                        
                        ASN1_TIME_free(thisupd);
                        ASN1_TIME_free(nextupd);
                    }
                }
                
                // Test OCSP_RESPID_match
                // Create a response ID and match it with certificate
                OCSP_RESPID *respid = OCSP_RESPID_new();
                if (respid) {
                    // Set response ID by name
                    OCSP_RESPID_set_by_name(respid, issuer_cert);
                    
                    // Test matching
                    OCSP_RESPID_match(respid, issuer_cert);
                    
                    OCSP_RESPID_free(respid);
                }
            }
            
            if (req) OCSP_REQUEST_free(req);
            if (bs) OCSP_BASICRESP_free(bs);
            break;
        }
        
        case 2: {
            // Test OCSP verification functions
            OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
            OCSP_REQUEST *req = OCSP_REQUEST_new();
            
            if (bs && req) {
                // Create certificate ID and add to both request and response
                const EVP_MD *dgst = EVP_sha256();
                OCSP_CERTID *cert_id = OCSP_cert_to_id(dgst, subject_cert, issuer_cert);
                
                if (cert_id) {
                    OCSP_request_add0_id(req, cert_id);
                    
                    // Create times
                    ASN1_TIME *thisupd = ASN1_TIME_new();
                    ASN1_TIME *nextupd = ASN1_TIME_new();
                    
                    if (thisupd && nextupd) {
                        time_t now = time(NULL);
                        ASN1_TIME_set(thisupd, now);
                        ASN1_TIME_set(nextupd, now + 7200); // 2 hours later
                        
                        // Add status
                        OCSP_basic_add1_status(bs, cert_id, cert_status,
                                            0, NULL, thisupd, nextupd);
                        
                        // Create certificate store for verification
                        X509_STORE *store = X509_STORE_new();
                        if (store) {
                            // Add issuer certificate to store
                            X509_STORE_add_cert(store, issuer_cert);
                            
                            // Create certificate stack
                            STACK_OF(X509) *certs = sk_X509_new_null();
                            if (certs) {
                                sk_X509_push(certs, issuer_cert);
                                
                                // Test OCSP_basic_verify with various flags
                                unsigned long flags = fdp.ConsumeIntegral<unsigned long>();
                                flags &= (OCSP_NOCHECKS | OCSP_NOVERIFY | OCSP_NOCHAIN | 
                                         OCSP_NOSIGS | OCSP_NOINTERN | OCSP_NOCERTS |
                                         OCSP_TRUSTOTHER | OCSP_NOEXPLICIT);
                                
                                OCSP_basic_verify(bs, certs, store, flags);
                                
                                sk_X509_free(certs);
                            }
                            
                            X509_STORE_free(store);
                        }
                        
                        ASN1_TIME_free(thisupd);
                        ASN1_TIME_free(nextupd);
                    }
                }
            }
            
            if (bs) OCSP_BASICRESP_free(bs);
            if (req) OCSP_REQUEST_free(req);
            break;
        }
        
        case 3: {
            // Test OCSP extension handling and printing variations
            OCSP_REQUEST *req = OCSP_REQUEST_new();
            
            if (req) {
                // Add multiple certificate IDs
                const EVP_MD *dgst1 = EVP_sha1();
                const EVP_MD *dgst2 = EVP_sha256();
                
                OCSP_CERTID *cert_id1 = OCSP_cert_to_id(dgst1, subject_cert, issuer_cert);
                OCSP_CERTID *cert_id2 = OCSP_cert_to_id(dgst2, NULL, issuer_cert); // No subject
                
                if (cert_id1) {
                    OCSP_request_add0_id(req, cert_id1);
                }
                if (cert_id2) {
                    OCSP_request_add0_id(req, cert_id2);
                }
                
                // Test various extension NIDs (using correct NID names from obj_mac.h)
                int test_nids[] = {NID_id_pkix_OCSP_Nonce, NID_id_pkix_OCSP_CrlID, 
                                  NID_id_pkix_OCSP_acceptableResponses, NID_id_pkix_OCSP_archiveCutoff};
                
                for (size_t i = 0; i < sizeof(test_nids)/sizeof(test_nids[0]); i++) {
                    int crit = 0;
                    int idx = -1;
                    void *ext_data = OCSP_REQUEST_get1_ext_d2i(req, test_nids[i], &crit, &idx);
                    if (ext_data) {
                        ASN1_TYPE_free((ASN1_TYPE *)ext_data);
                    }
                }
                
                // Test printing with different BIOs
                BIO *mem_bio = BIO_new(BIO_s_mem());
                BIO *null_bio = BIO_new(BIO_s_null()); // /dev/null equivalent
                
                if (mem_bio) {
                    OCSP_REQUEST_print(mem_bio, req, OCSP_NOCERTS);
                    BIO_free(mem_bio);
                }
                
                if (null_bio) {
                    OCSP_REQUEST_print(null_bio, req, OCSP_NOVERIFY);
                    BIO_free(null_bio);
                }
                
                OCSP_REQUEST_free(req);
            }
            break;
        }
    }
    
    // Cleanup synthetic certificates
    if (issuer_name) X509_NAME_free(issuer_name);
    if (subject_name) X509_NAME_free(subject_name);
    if (issuer_cert) X509_free(issuer_cert);
    if (subject_cert) X509_free(subject_cert);
    
    return 0;
}
