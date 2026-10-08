/*
 * Fuzzing harness for OpenSSL OCSP (Online Certificate Status Protocol) functions
 * Targets: OCSP extension handling and response stack manipulation with 0% coverage
 * Specific APIs: OCSP_ONEREQ_add1_ext_i2d, sk_OCSP_RESPONSE_new_null, sk_OCSP_RESPONSE_push,
 *               sk_OCSP_RESPONSE_pop_free, sk_OCSP_RESPONSE_value
 * Coverage goal: Unlock 300+ undiscovered branches in OCSP extension handling
 * Semantic differentiation: Focus on OCSP extension manipulation and response stack operations
 *                          (vs. basic OCSP request/response lifecycle in harness_002.cpp)
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
    if (size < 128) {
        return 0; // Need minimum input for meaningful OCSP extension testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | 
                       OPENSSL_INIT_ADD_ALL_CIPHERS | 
                       OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    ERR_clear_error();
    
    // Determine which OCSP operation to test based on first byte
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    // Consume parameters that will be used across all operations
    int nid = fdp.ConsumeIntegralInRange<int>(1, 1000); // Extension NID
    int crit = fdp.ConsumeBool() ? 1 : 0; // Critical flag
    unsigned long flags = fdp.ConsumeIntegral<unsigned long>();
    
    // Create synthetic certificates for testing using fuzzed data
    X509 *issuer_cert = X509_new();
    X509 *subject_cert = X509_new();
    
    if (issuer_cert == NULL || subject_cert == NULL) {
        if (issuer_cert) X509_free(issuer_cert);
        if (subject_cert) X509_free(subject_cert);
        return 0;
    }
    
    // Set some basic fields on the synthetic certificates
    X509_NAME *issuer_name = X509_NAME_new();
    X509_NAME *subject_name = X509_NAME_new();
    
    if (issuer_name && subject_name) {
        // Add entries to the names using fuzzed input
        size_t issuer_name_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        size_t subject_name_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        std::string issuer_name_str = fdp.ConsumeBytesAsString(issuer_name_len);
        std::string subject_name_str = fdp.ConsumeBytesAsString(subject_name_len);
        
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
        long serial_number = fdp.ConsumeIntegral<long>();
        ASN1_INTEGER *serial = ASN1_INTEGER_new();
        if (serial) {
            ASN1_INTEGER_set(serial, serial_number);
            X509_set_serialNumber(subject_cert, serial);
            ASN1_INTEGER_free(serial);
        }
    }
    
    // Test X509_dup as mentioned in guidance
    X509 *dup_issuer_cert = NULL;
    X509 *dup_subject_cert = NULL;
    if (issuer_cert) {
        dup_issuer_cert = X509_dup(issuer_cert);
    }
    if (subject_cert) {
        dup_subject_cert = X509_dup(subject_cert);
    }
    
    switch (operation) {
        case 0: {
            // Test OCSP_ONEREQ_add1_ext_i2d - OCSP extension handling
            OCSP_REQUEST *req = OCSP_REQUEST_new();
            if (req == NULL) {
                break;
            }
            
            // Create certificate ID using OCSP_cert_to_id
            const EVP_MD *dgst = EVP_sha256();
            OCSP_CERTID *cert_id = OCSP_cert_to_id(dgst, subject_cert, issuer_cert);
            if (cert_id) {
                // Add certificate ID to request to create OCSP_ONEREQ
                OCSP_ONEREQ *one_req = OCSP_request_add0_id(req, cert_id);
                if (one_req) {
                    // Test OCSP_ONEREQ_add1_ext_i2d with various value types
                    // Create different types of extension values based on fuzzed input
                    
                    // Test 1: Integer value - create ASN1_INTEGER structure
                    int int_value = fdp.ConsumeIntegral<int>();
                    ASN1_INTEGER *asn1_int = ASN1_INTEGER_new();
                    if (asn1_int) {
                        ASN1_INTEGER_set(asn1_int, int_value);
                        // Create ASN1_TYPE containing the integer
                        ASN1_TYPE *asn1_type_int = ASN1_TYPE_new();
                        if (asn1_type_int) {
                            ASN1_TYPE_set(asn1_type_int, V_ASN1_INTEGER, asn1_int);
                            OCSP_ONEREQ_add1_ext_i2d(one_req, nid, asn1_type_int, crit, flags);
                            ASN1_TYPE_free(asn1_type_int);
                        } else {
                            // If ASN1_TYPE_new failed, free asn1_int
                            ASN1_INTEGER_free(asn1_int);
                        }
                    }
                    
                    // Test 2: String value - create ASN1_OCTET_STRING structure
                    size_t str_len = fdp.ConsumeIntegralInRange<size_t>(1, 128);
                    std::string str_value = fdp.ConsumeBytesAsString(str_len);
                    if (!str_value.empty()) {
                        ASN1_OCTET_STRING *asn1_oct = ASN1_OCTET_STRING_new();
                        if (asn1_oct) {
                            ASN1_OCTET_STRING_set(asn1_oct, (const unsigned char *)str_value.c_str(), str_value.length());
                            // Create ASN1_TYPE containing the octet string
                            ASN1_TYPE *asn1_type_oct = ASN1_TYPE_new();
                            if (asn1_type_oct) {
                                ASN1_TYPE_set(asn1_type_oct, V_ASN1_OCTET_STRING, asn1_oct);
                                OCSP_ONEREQ_add1_ext_i2d(one_req, nid, asn1_type_oct, crit, flags);
                                ASN1_TYPE_free(asn1_type_oct);
                            } else {
                                // If ASN1_TYPE_new failed, free asn1_oct
                                ASN1_OCTET_STRING_free(asn1_oct);
                            }
                        }
                    }
                    
                    // Test 3: ASN1_TYPE value with various types
                    ASN1_TYPE *asn1_value = ASN1_TYPE_new();
                    if (asn1_value) {
                        // Set ASN1_TYPE based on fuzzed input type
                        // Generate a type from a reasonable range of ASN.1 types
                        int asn1_type = fdp.ConsumeIntegralInRange<int>(V_ASN1_INTEGER, V_ASN1_BMPSTRING);
                        // For simplicity, create appropriate data based on type
                        switch (asn1_type) {
                            case V_ASN1_INTEGER:
                            case V_ASN1_ENUMERATED: {
                                // INTEGER and ENUMERATED types use ASN1_INTEGER structure
                                ASN1_INTEGER *asn1_int2 = ASN1_INTEGER_new();
                                if (asn1_int2) {
                                    ASN1_INTEGER_set(asn1_int2, fdp.ConsumeIntegral<long>());
                                    ASN1_TYPE_set(asn1_value, asn1_type, asn1_int2);
                                    // Note: ASN1_TYPE_set takes ownership of asn1_int2, do NOT free it
                                }
                                break;
                            }
                            case V_ASN1_BIT_STRING:
                            case V_ASN1_OCTET_STRING:
                            case V_ASN1_UTF8STRING:
                            case V_ASN1_NUMERICSTRING:
                            case V_ASN1_PRINTABLESTRING:
                            case V_ASN1_T61STRING:
                            case V_ASN1_VIDEOTEXSTRING:
                            case V_ASN1_IA5STRING:
                            case V_ASN1_GRAPHICSTRING:
                            case V_ASN1_VISIBLESTRING:
                            case V_ASN1_GENERALSTRING:
                            case V_ASN1_UNIVERSALSTRING:
                            case V_ASN1_BMPSTRING: {
                                // For string types, create an ASN1_STRING structure
                                ASN1_STRING *asn1_str = ASN1_STRING_new();
                                if (asn1_str) {
                                    size_t data_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
                                    std::vector<uint8_t> str_data = fdp.ConsumeBytes<uint8_t>(data_len);
                                    ASN1_STRING_set(asn1_str, str_data.data(), str_data.size());
                                    ASN1_TYPE_set(asn1_value, asn1_type, asn1_str);
                                    // Note: ASN1_TYPE_set takes ownership of asn1_str, do NOT free it
                                }
                                break;
                            }
                            case V_ASN1_UTCTIME:
                            case V_ASN1_GENERALIZEDTIME: {
                                // For time types, create an ASN1_TIME structure
                                ASN1_TIME *asn1_time = ASN1_TIME_new();
                                if (asn1_time) {
                                    size_t data_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
                                    std::vector<uint8_t> time_data = fdp.ConsumeBytes<uint8_t>(data_len);
                                    ASN1_STRING_set(asn1_time, time_data.data(), time_data.size());
                                    ASN1_TYPE_set(asn1_value, asn1_type, asn1_time);
                                    // Note: ASN1_TYPE_set takes ownership of asn1_time, do NOT free it
                                }
                                break;
                            }
                            case V_ASN1_NULL: {
                                // For NULL type, just set with NULL
                                ASN1_TYPE_set(asn1_value, V_ASN1_NULL, NULL);
                                break;
                            }
                            case V_ASN1_OBJECT: {
                                // Create a simple object identifier
                                ASN1_OBJECT *asn1_obj = OBJ_nid2obj(fdp.ConsumeIntegralInRange<int>(1, 100));
                                if (asn1_obj) {
                                    ASN1_TYPE_set(asn1_value, V_ASN1_OBJECT, asn1_obj);
                                    // Note: OBJ_nid2obj returns a pointer that should not be freed
                                }
                                break;
                            }
                            case V_ASN1_REAL: {
                                // For REAL type, we need an ASN1_REAL structure
                                // Skip REAL for now as it's complex to create properly
                                ASN1_TYPE_free(asn1_value);
                                asn1_value = NULL;
                                break;
                            }
                            case V_ASN1_SEQUENCE:
                            case V_ASN1_SET: {
                                // For constructed types, we would need to create proper encoding
                                // For now, skip these complex types to avoid crashes
                                ASN1_TYPE_free(asn1_value);
                                asn1_value = NULL;
                                break;
                            }
                            case V_ASN1_OBJECT_DESCRIPTOR:
                            case V_ASN1_EXTERNAL:
                            case V_ASN1_EOC:
                            case V_ASN1_BOOLEAN:
                            default:
                                // For other types that are not commonly used or would be complex to create,
                                // skip to avoid invalid NULL values or crashes
                                ASN1_TYPE_free(asn1_value);
                                asn1_value = NULL;
                                break;
                        }
                        if (asn1_value) {
                            OCSP_ONEREQ_add1_ext_i2d(one_req, nid, asn1_value, crit, flags);
                            ASN1_TYPE_free(asn1_value);
                        }
                    }
                    
                    // Test OCSP_ONEREQ extension retrieval functions
                    int ext_count = OCSP_ONEREQ_get_ext_count(one_req);
                    for (int i = 0; i < ext_count; i++) {
                        const X509_EXTENSION *ext = OCSP_ONEREQ_get_ext(one_req, i);
                        if (ext) {
                            // Get extension data
                            int ext_crit = 0;
                            int idx = -1;
                            void *ext_data = OCSP_ONEREQ_get1_ext_d2i(one_req, nid, &ext_crit, &idx);
                            if (ext_data) {
                                // Extension data returned by get1_ext_d2i should be freed with
                                // the appropriate type-specific free function, which we cannot
                                // determine for arbitrary NIDs. Do not free to avoid double-free.
                                // The extension data will be freed when the OCSP_ONEREQ is freed.
                            }
                        }
                    }
                }
            }
            
            OCSP_REQUEST_free(req);
            break;
        }
        case 1: {
            // Test OCSP response stack manipulation functions
            // Create OCSP response stack using sk_OCSP_RESPONSE_new_null
            STACK_OF(OCSP_RESPONSE) *resp_stack = sk_OCSP_RESPONSE_new_null();
            if (resp_stack == NULL) {
                break;
            }
            
            // Create multiple OCSP responses and push them to stack
            int num_responses = fdp.ConsumeIntegralInRange<int>(1, 5);
            
            for (int i = 0; i < num_responses; i++) {
                if (fdp.remaining_bytes() < 32) break;
                
                // Create a basic OCSP response
                OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
                OCSP_REQUEST *req = OCSP_REQUEST_new();
                
                if (bs && req) {
                    // Create certificate ID
                    const EVP_MD *dgst = EVP_sha256();
                    OCSP_CERTID *cert_id = OCSP_cert_to_id(dgst, subject_cert, issuer_cert);
                    
                    if (cert_id) {
                        OCSP_request_add0_id(req, cert_id);
                        
                        // Create times for response
                        ASN1_TIME *thisupd = ASN1_TIME_new();
                        ASN1_TIME *nextupd = ASN1_TIME_new();
                        
                        if (thisupd && nextupd) {
                            // Use fuzzed input for time values
                            long time_val = fdp.ConsumeIntegral<long>();
                            ASN1_UTCTIME_set(thisupd, time_val);
                            ASN1_UTCTIME_set(nextupd, time_val + 3600);
                            
                            // Add status to basic response
                            int cert_status = fdp.ConsumeIntegralInRange<int>(0, 2);
                            OCSP_basic_add1_status(bs, cert_id, cert_status, 
                                                 0, NULL, thisupd, nextupd);
                            
                            // Create OCSP response with various status codes
                            int resp_status = fdp.ConsumeIntegralInRange<int>(0, 6);
                            OCSP_RESPONSE *resp = OCSP_response_create(resp_status, bs);
                            
                            if (resp) {
                                // Push response to stack using sk_OCSP_RESPONSE_push
                                sk_OCSP_RESPONSE_push(resp_stack, resp);
                            }
                            
                            ASN1_TIME_free(thisupd);
                            ASN1_TIME_free(nextupd);
                        }
                    }
                    
                    if (req) OCSP_REQUEST_free(req);
                    if (bs) OCSP_BASICRESP_free(bs);
                }
            }
            
            // Test sk_OCSP_RESPONSE_value to retrieve responses from stack
            int stack_size = sk_OCSP_RESPONSE_num(resp_stack);
            for (int i = 0; i < stack_size; i++) {
                OCSP_RESPONSE *resp = sk_OCSP_RESPONSE_value(resp_stack, i);
                if (resp) {
                    // Test OCSP response status
                    int status = OCSP_response_status(resp);
                    
                    // Try to get basic response
                    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
                    if (bs) {
                        // Test basic response verification with fuzzed flags
                        unsigned long verify_flags = fdp.ConsumeIntegral<unsigned long>();
                        verify_flags &= (OCSP_NOCHECKS | OCSP_NOVERIFY | OCSP_NOCHAIN | 
                                       OCSP_NOSIGS | OCSP_NOINTERN | OCSP_NOCERTS |
                                       OCSP_TRUSTOTHER | OCSP_NOEXPLICIT);
                        
                        // Create a simple certificate store for verification
                        X509_STORE *store = X509_STORE_new();
                        if (store) {
                            X509_STORE_add_cert(store, issuer_cert);
                            STACK_OF(X509) *certs = sk_X509_new_null();
                            if (certs) {
                                sk_X509_push(certs, issuer_cert);
                                OCSP_basic_verify(bs, certs, store, verify_flags);
                                sk_X509_free(certs);
                            }
                            X509_STORE_free(store);
                        }
                        
                        OCSP_BASICRESP_free(bs);
                    }
                }
            }
            
            // Clean up stack using sk_OCSP_RESPONSE_pop_free
            sk_OCSP_RESPONSE_pop_free(resp_stack, OCSP_RESPONSE_free);
            break;
        }
        
        case 2: {
            // Test combined workflow: OCSP extension + response stack
            OCSP_REQUEST *req = OCSP_REQUEST_new();
            if (req == NULL) {
                break;
            }
            
            // Create certificate ID
            const EVP_MD *dgst = EVP_sha256();
            OCSP_CERTID *cert_id = OCSP_cert_to_id(dgst, subject_cert, issuer_cert);
            
            if (cert_id) {
                OCSP_ONEREQ *one_req = OCSP_request_add0_id(req, cert_id);
                if (one_req) {
                    // Add extension to OCSP request with proper ASN.1 structure
                    // Add extension to OCSP request with proper ASN.1 structure
                    int ext_nid = fdp.ConsumeIntegralInRange<int>(1, 1000);
                    int ext_value = fdp.ConsumeIntegral<int>();
                    ASN1_INTEGER *asn1_ext_int = ASN1_INTEGER_new();
                    if (asn1_ext_int) {
                        ASN1_INTEGER_set(asn1_ext_int, ext_value);
                        ASN1_TYPE *asn1_ext_type = ASN1_TYPE_new();
                        if (asn1_ext_type) {
                            ASN1_TYPE_set(asn1_ext_type, V_ASN1_INTEGER, asn1_ext_int);
                            OCSP_ONEREQ_add1_ext_i2d(one_req, ext_nid, asn1_ext_type, 0, 0);
                            ASN1_TYPE_free(asn1_ext_type); // This frees asn1_ext_int as well
                        } else {
                            // If ASN1_TYPE_new failed, free asn1_ext_int
                            ASN1_INTEGER_free(asn1_ext_int);
                        }
                    }
                } // Close the if (one_req) block
                
                // Create response stack
                STACK_OF(OCSP_RESPONSE) *resp_stack = sk_OCSP_RESPONSE_new_null();
                if (resp_stack) {
                    // Create a response and push to stack
                    OCSP_BASICRESP *bs = OCSP_BASICRESP_new();
                    if (bs) {
                        // Create times
                        ASN1_TIME *thisupd = ASN1_TIME_new();
                        ASN1_TIME *nextupd = ASN1_TIME_new();
                        
                        if (thisupd && nextupd) {
                            long time_val = fdp.ConsumeIntegral<long>();
                            ASN1_UTCTIME_set(thisupd, time_val);
                            ASN1_UTCTIME_set(nextupd, time_val + 7200);
                            
                            int cert_status = fdp.ConsumeIntegralInRange<int>(0, 2);
                            OCSP_basic_add1_status(bs, cert_id, cert_status, 
                                                 0, NULL, thisupd, nextupd);
                            
                            int resp_status = fdp.ConsumeIntegralInRange<int>(0, 6);
                            OCSP_RESPONSE *resp = OCSP_response_create(resp_status, bs);
                            
                            if (resp) {
                                sk_OCSP_RESPONSE_push(resp_stack, resp);
                                
                                // Retrieve and verify
                                OCSP_RESPONSE *stack_resp = sk_OCSP_RESPONSE_value(resp_stack, 0);
                                if (stack_resp) {
                                    // Test response printing with fuzzed flags
                                    BIO *bio = BIO_new(BIO_s_null());
                                    if (bio) {
                                        unsigned long print_flags = fdp.ConsumeIntegral<unsigned long>();
                                        OCSP_RESPONSE_print(bio, stack_resp, print_flags);
                                        BIO_free(bio);
                                    }
                                }
                            }
                            
                            ASN1_TIME_free(thisupd);
                            ASN1_TIME_free(nextupd);
                        }
                        OCSP_BASICRESP_free(bs);
                    }
                    
                    sk_OCSP_RESPONSE_pop_free(resp_stack, OCSP_RESPONSE_free);
                }
            }
            
            OCSP_REQUEST_free(req);
            break;
        }
    }
    
    // Cleanup
    if (issuer_name) X509_NAME_free(issuer_name);
    if (subject_name) X509_NAME_free(subject_name);
    if (issuer_cert) X509_free(issuer_cert);
    if (subject_cert) X509_free(subject_cert);
    if (dup_issuer_cert) X509_free(dup_issuer_cert);
    if (dup_subject_cert) X509_free(dup_subject_cert);
    
    return 0;
}
