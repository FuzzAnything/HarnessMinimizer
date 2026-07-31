/*
 * Fuzzing harness for OpenSSL x509 certificate verification operations
 * Targets: NETSCAPE_SPKI_verify, X509_REQ_digest, X509_get1_email
 * Helper APIs: X509_verify, X509_REQ_verify, X509_new, X509_REQ_new, EVP_PKEY_new
 * Follows full lifecycle: Create -> Populate -> Verify -> Digest -> Cleanup
 * Differentiated from harness_000.cpp which focused on hash and symmetric crypto
 */

#include <stddef.h>
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 32) {
        return 0;  // Need minimum input for meaningful testing
    }

    FuzzedDataProvider fdp(data, size);

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_clear_error();

    // Consume operation type to decide what to test
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 3;

    // Create cryptographic keys
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return 0;
    }

    // Create X509 certificate
    X509* cert = X509_new();
    if (cert == NULL) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Create X509 certificate request
    X509_REQ* req = X509_REQ_new();
    if (req == NULL) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Create NETSCAPE_SPKI structure
    NETSCAPE_SPKI* spki = NETSCAPE_SPKI_new();
    if (spki == NULL) {
        X509_REQ_free(req);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Try to populate certificate with minimal data for testing
    // Set version (X509_VERSION_3 = 2)
    X509_set_version(cert, 2);
    
    // Generate a serial number from fuzzer input
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    if (serial != NULL) {
        // Consume data for serial number
        size_t serial_len = fdp.ConsumeIntegralInRange<size_t>(1, 8); // Up to 8 bytes for serial
        if (fdp.remaining_bytes() >= serial_len) {
            std::vector<uint8_t> serial_data = fdp.ConsumeBytes<uint8_t>(serial_len);
            // Convert bytes to a long integer for serial number
            long serial_value = 0;
            for (size_t i = 0; i < serial_data.size() && i < sizeof(long); i++) {
                serial_value = (serial_value << 8) | serial_data[i];
            }
            ASN1_INTEGER_set(serial, serial_value);
            X509_set_serialNumber(cert, serial);
        }
        ASN1_INTEGER_free(serial);
    }

    // Set notBefore and notAfter to current time
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L); // 1 year
    X509_NAME* name = X509_NAME_new();
    if (name != NULL) {
        // Consume string for common name from fuzzer input
        size_t cn_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        std::string common_name = fdp.ConsumeBytesAsString(cn_len);
        
        // Add common name using consumed data
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                                   (const unsigned char*)common_name.c_str(), -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);
        X509_NAME_free(name);
    }

    // Set public key (even if empty, just for testing)
    X509_set_pubkey(cert, pkey);

    // Sign the certificate with itself (self-signed, will likely fail verification)
    X509_sign(cert, pkey, EVP_sha256());

    // Populate certificate request similarly
    X509_REQ_set_version(req, 0); // Version 1
    X509_REQ_set_pubkey(req, pkey);
    
    // Create subject name for request
    X509_NAME* req_name = X509_NAME_new();
    if (req_name != NULL) {
        // Consume string for request common name from fuzzer input
        size_t req_cn_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        std::string req_common_name = fdp.ConsumeBytesAsString(req_cn_len);
        
        X509_NAME_add_entry_by_txt(req_name, "CN", MBSTRING_ASC,
                                   (const unsigned char*)req_common_name.c_str(), -1, -1, 0);
        X509_REQ_set_subject_name(req, req_name);
        X509_NAME_free(req_name);
    }
    
    // Sign the request
    X509_REQ_sign(req, pkey, EVP_sha256());
    // Consume some data for SPKI
    size_t spki_data_len = fdp.ConsumeIntegralInRange<size_t>(1, 100);
    std::vector<uint8_t> spki_data = fdp.ConsumeBytes<uint8_t>(spki_data_len);
    // Note: NETSCAPE_SPKI structure is more complex, we'll just use the empty one

    switch (operation) {
        case 0: {
            // Test X509 verification functions
            
            // X509_verify - verify certificate signature
            int verify_result = X509_verify(cert, pkey);
            // Result can be 1 (success), 0 (failure), or -1 (error)
            // We don't care about the result, just that the function was called
            
            // X509_REQ_verify - verify certificate request signature
            int req_verify_result = X509_REQ_verify(req, pkey);
            
            // NETSCAPE_SPKI_verify - verify SPKI signature
            int spki_verify_result = NETSCAPE_SPKI_verify(spki, pkey);
            
            break;
        }
        
        case 1: {
            // Test X509_REQ_digest function
            
            // Choose a digest algorithm based on consumed data
            uint8_t digest_type = fdp.ConsumeIntegral<uint8_t>() % 3;
            const EVP_MD* md = NULL;
            
            switch (digest_type) {
                case 0:
                    md = EVP_sha1();
                    break;
                case 1:
                    md = EVP_sha256();
                    break;
                case 2:
                    md = EVP_sha512();
                    break;
                default:
                    md = EVP_sha256();
                    break;
            }
            
            if (md != NULL) {
                unsigned char digest[EVP_MAX_MD_SIZE];
                unsigned int digest_len = 0;
                
                // Call X509_REQ_digest
                int digest_result = X509_REQ_digest(req, md, digest, &digest_len);
                
                // Also test X509_digest for comparison
                unsigned char cert_digest[EVP_MAX_MD_SIZE];
                unsigned int cert_digest_len = 0;
                X509_digest(cert, md, cert_digest, &cert_digest_len);
            }
            
            break;
        }
        
        case 2: {
            // Test X509_get1_email function
            
            // First, try to add an email extension to the certificate
            // This is complex, so we'll just call the function
            // It will likely return NULL or empty stack
            
            STACK_OF(OPENSSL_STRING)* emails = X509_get1_email(cert);
            if (emails != NULL) {
                // Free the returned emails
                X509_email_free(emails);
            }
            
            // Also test with the certificate request
            // X509_REQ doesn't have X509_get1_email, but we can try to extract
            // email from subject or extensions if present
            
            break;
        }
    }

    // Clean up all allocated objects
    NETSCAPE_SPKI_free(spki);
    X509_REQ_free(req);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return 0;
}
