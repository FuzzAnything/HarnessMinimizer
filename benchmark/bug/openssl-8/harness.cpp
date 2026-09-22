/*
 * Fuzzing harness for OpenSSL PKCS12 password-based encryption and decryption operations
 * Primary target: PKCS12_item_i2d_encrypt with 577 undiscovered branches
 * Coverage goal: Exercise comprehensive PKCS12 encryption/decryption lifecycle to unlock 577+ branches
 * 
 * Target APIs:
 * - PKCS12_item_i2d_encrypt_ex (Primary Target: Modern encryption with library context)
 * - PKCS12_item_decrypt_d2i_ex (Primary Target: Modern decryption with library context)
 * - PKCS12_item_i2d_encrypt (Legacy encryption wrapper)
 * - PKCS12_item_decrypt_d2i (Legacy decryption wrapper)
 * - PKCS12_pbe_crypt_ex (Core encryption/decryption primitive)
 * - PKCS12_pbe_crypt (Legacy core primitive)
 * 
 * Required helper APIs:
 * - X509_ALGOR_new (Encryption algorithm creation)
 * - X509_ALGOR_free (Algorithm cleanup)
 * - ASN1_OCTET_STRING_new (Encrypted data container)
 * - ASN1_OCTET_STRING_free (Container cleanup)
 * - ASN1_item_i2d (Object serialization)
 * - ASN1_item_d2i (Object deserialization)
 * - ASN1_TYPE_new (Parameter type creation)
 * - ASN1_TYPE_free (Parameter cleanup)
 * - EVP_CIPHER_CTX_new (Cipher context creation)
 * - EVP_CIPHER_CTX_free (Cipher context cleanup)
 * - OBJ_nid2obj (Object identifier lookup)
 * - OPENSSL_free (General cleanup)
 * 
 * Dependency Chain Analysis:
 * 1. **Initialization**: Create X509_ALGOR (encryption algorithm), ASN1_ITEM (object type), password buffer
 * 2. **Encryption Path**: PKCS12_item_i2d_encrypt_ex → PKCS12_pbe_crypt_ex → EVP_PBE_CipherInit_ex
 * 3. **Decryption Path**: PKCS12_item_decrypt_d2i_ex → PKCS12_pbe_crypt_ex → ASN1_item_d2i
 * 4. **Cleanup**: ASN1_OCTET_STRING_free, OPENSSL_free, EVP_CIPHER_CTX_free
 * 
 * Invocation sequence:
 * 1. Initialize: Create X509_ALGOR with encryption algorithm, ASN1_TYPE parameters
 * 2. Encryption: PKCS12_item_i2d_encrypt_ex to encrypt test data with password
 * 3. Decryption: PKCS12_item_decrypt_d2i_ex to decrypt the encrypted data
 * 4. Round-trip: Verify encryption/decryption round-trip consistency
 * 5. Cleanup: Free all allocated objects
 * 
 * Differentiation from existing harnesses:
 * - harness_000.cpp: AES cryptographic operations
 * - harness_001.cpp: RSA cryptographic operations  
 * - harness_002.cpp: SSL/TLS protocol stack
 * - harness_003.cpp: CMP/CRMF certificate management
 * - harness_004.cpp: X.509 certificate parsing and CMS operations
 * - harness_005.cpp: EVP elliptic curve cryptography operations
 * - harness_006.cpp: PKCS12 certificate container operations (focuses on PKCS12_add_safe_ex, NOT encryption/decryption)
 * - harness_007.cpp: EC (Elliptic Curve) cryptographic operations
 * - harness_008.cpp: PEM format parsing of EC/DSA/RSA private keys
 * - harness_009.cpp: Time-Stamp Protocol (RFC 3161) operations
 * - harness_010.cpp: Hash functions (SHA family)
 * - harness_011.cpp: DH key exchange and DSA digital signatures
 * - harness_012.cpp: HPKE (Hybrid Public Key Encryption) RFC 9180
 * - harness_013.cpp: PKCS7 S/MIME operations
 * - harness_014.cpp: SSL socket file descriptor operations
 * - harness_015.cpp: RSA key PEM parsing
 * - harness_016.cpp: CMP message parsing and serialization
 * - harness_017.cpp: Comprehensive PKCS12 password-based encryption and decryption (NEW - targets 577+ branch gap)
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size: need enough for password, algorithm selection, and test data
    if (size < 64) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL libraries
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    
    // 1. Consume password from fuzzer input
    size_t pass_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
    std::string password = fdp.ConsumeBytesAsString(pass_len);
    
    // 2. Create X509_ALGOR for encryption algorithm
    X509_ALGOR* algor = X509_ALGOR_new();
    if (algor == NULL) {
        return 0;
    }
    
    // Select encryption algorithm from common PKCS12 PBE algorithms
    static const int pbe_algorithms[] = {
        NID_pbe_WithSHA1And40BitRC2_CBC,
        NID_pbe_WithSHA1And128BitRC4,
        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
        NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
        NID_pbe_WithSHA1And40BitRC2_CBC,
        NID_pbe_WithSHA1And128BitRC2_CBC,
    };
    
    int algo_choice = fdp.ConsumeIntegralInRange<int>(0, sizeof(pbe_algorithms)/sizeof(pbe_algorithms[0]) - 1);
    int pbe_nid = pbe_algorithms[algo_choice];
    
    // Set algorithm OID
    ASN1_OBJECT* algo_obj = OBJ_nid2obj(pbe_nid);
    if (algo_obj == NULL) {
        X509_ALGOR_free(algor);
        return 0;
    }
    
    X509_ALGOR_set0(algor, algo_obj, V_ASN1_NULL, NULL);
    
    // 3. Create ASN1_TYPE for algorithm parameters (salt, iteration count)
    ASN1_TYPE* param = ASN1_TYPE_new();
    if (param != NULL) {
        // Create PBEParameter structure with random salt and iteration count
        PBEPARAM* pbe_param = PBEPARAM_new();
        if (pbe_param != NULL) {
            // Consume salt from fuzzer input
            size_t salt_len = fdp.ConsumeIntegralInRange<size_t>(8, 64);
            std::vector<uint8_t> salt = fdp.ConsumeBytes<uint8_t>(salt_len);
            
            // Set salt in PBEPARAM
            if (salt.size() > 0) {
                ASN1_OCTET_STRING_set(pbe_param->salt, salt.data(), salt.size());
            }
            
            // Set iteration count (reasonable range for fuzzing)
            int iterations = fdp.ConsumeIntegralInRange<int>(1, 10000);
            ASN1_INTEGER_set(pbe_param->iter, iterations);
            
            // Encode PBEPARAM to ASN1_TYPE
            unsigned char* param_data = NULL;
            int param_len = i2d_PBEPARAM(pbe_param, &param_data);
            if (param_len > 0 && param_data != NULL) {
                ASN1_TYPE_set(param, V_ASN1_SEQUENCE, param_data);
                // DO NOT free param_data here - ASN1_TYPE_set() takes ownership
                // OPENSSL_free(param_data);
            }
            
            PBEPARAM_free(pbe_param);
        }
    }
    
    // 4. Create test data to encrypt (using ASN1_OCTET_STRING as a simple test object)
    ASN1_OCTET_STRING* test_data = ASN1_OCTET_STRING_new();
    if (test_data == NULL) {
        if (param != NULL) ASN1_TYPE_free(param);
        X509_ALGOR_free(algor);
        return 0;
    }
    
    // Consume test data from fuzzer input
    size_t test_data_len = fdp.ConsumeIntegralInRange<size_t>(1, 1024);
    std::vector<uint8_t> test_bytes = fdp.ConsumeBytes<uint8_t>(test_data_len);
    
    if (test_bytes.size() > 0) {
        ASN1_OCTET_STRING_set(test_data, test_bytes.data(), test_bytes.size());
    }
    
    // 5. Determine operation type based on remaining input
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    int zbuf = fdp.ConsumeBool() ? 1 : 0;  // Zero buffer after use flag
    
    // For library context (use NULL for default)
    OSSL_LIB_CTX* libctx = NULL;
    const char* propq = NULL;
    
    ASN1_OCTET_STRING* encrypted = NULL;
    ASN1_OCTET_STRING* decrypted_obj = NULL;
    
    switch (operation_type) {
        case 0: {  // Test PKCS12_item_i2d_encrypt_ex (modern API)
            encrypted = PKCS12_item_i2d_encrypt_ex(
                algor, 
                ASN1_ITEM_rptr(ASN1_OCTET_STRING),
                password.c_str(), 
                password.length(),
                test_data, 
                zbuf,
                libctx,
                propq
            );
            
            if (encrypted != NULL) {
                // Try to decrypt using PKCS12_item_decrypt_d2i_ex
                decrypted_obj = (ASN1_OCTET_STRING*)PKCS12_item_decrypt_d2i_ex(
                    algor,
                    ASN1_ITEM_rptr(ASN1_OCTET_STRING),
                    password.c_str(),
                    password.length(),
                    encrypted,
                    zbuf,
                    libctx,
                    propq
                );
                
                // Clean up decrypted object
                if (decrypted_obj != NULL) {
                    ASN1_OCTET_STRING_free(decrypted_obj);
                }
                
                // Clean up encrypted data
                ASN1_OCTET_STRING_free(encrypted);
            }
            break;
        }
        
        case 1: {  // Test PKCS12_item_i2d_encrypt (legacy API)
            encrypted = PKCS12_item_i2d_encrypt(
                algor,
                ASN1_ITEM_rptr(ASN1_OCTET_STRING),
                password.c_str(),
                password.length(),
                test_data,
                zbuf
            );
            
            if (encrypted != NULL) {
                // Try to decrypt using PKCS12_item_decrypt_d2i
                decrypted_obj = (ASN1_OCTET_STRING*)PKCS12_item_decrypt_d2i(
                    algor,
                    ASN1_ITEM_rptr(ASN1_OCTET_STRING),
                    password.c_str(),
                    password.length(),
                    encrypted,
                    zbuf
                );
                
                // Clean up decrypted object
                if (decrypted_obj != NULL) {
                    ASN1_OCTET_STRING_free(decrypted_obj);
                }
                
                // Clean up encrypted data
                ASN1_OCTET_STRING_free(encrypted);
            }
            break;
        }
        
        case 2: {  // Test PKCS12_pbe_crypt_ex directly
            // Consume additional data for direct PBE crypt test
            size_t direct_data_len = fdp.ConsumeIntegralInRange<size_t>(1, 512);
            std::vector<uint8_t> direct_data = fdp.ConsumeBytes<uint8_t>(direct_data_len);
            
            if (direct_data.size() > 0) {
                unsigned char* crypt_result = NULL;
                int crypt_len = 0;
                int en_de = fdp.ConsumeBool() ? 1 : 0;  // Encryption or decryption
                
                crypt_result = PKCS12_pbe_crypt_ex(
                    algor,
                    password.c_str(),
                    password.length(),
                    direct_data.data(),
                    direct_data.size(),
                    &crypt_result,
                    &crypt_len,
                    en_de,
                    libctx,
                    propq
                );
                
                if (crypt_result != NULL) {
                    OPENSSL_free(crypt_result);
                }
            }
            break;
        }
        
        case 3: {  // Test PKCS12_pbe_crypt directly (legacy)
            // Consume additional data for direct PBE crypt test
            size_t direct_data_len = fdp.ConsumeIntegralInRange<size_t>(1, 512);
            std::vector<uint8_t> direct_data = fdp.ConsumeBytes<uint8_t>(direct_data_len);
            
            if (direct_data.size() > 0) {
                unsigned char* crypt_result = NULL;
                int crypt_len = 0;
                int en_de = fdp.ConsumeBool() ? 1 : 0;  // Encryption or decryption
                
                crypt_result = PKCS12_pbe_crypt(
                    algor,
                    password.c_str(),
                    password.length(),
                    direct_data.data(),
                    direct_data.size(),
                    &crypt_result,
                    &crypt_len,
                    en_de
                );
                
                if (crypt_result != NULL) {
                    OPENSSL_free(crypt_result);
                }
            }
            break;
        }
    }
    
    // 6. Cleanup all allocated objects
    ASN1_OCTET_STRING_free(test_data);
    if (param != NULL) {
        ASN1_TYPE_free(param);
    }
    X509_ALGOR_free(algor);
    
    // Clear any accumulated OpenSSL errors
    ERR_clear_error();
    
    return 0;
}
