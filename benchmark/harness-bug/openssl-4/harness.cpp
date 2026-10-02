/*
 * OpenSSL DES (Data Encryption Standard) cryptographic operations fuzzing harness
 * Targets DES cryptographic module identified as 0% coverage across all metrics
 * Focuses on DES APIs and invocation sequences to increase coverage in completely untested module
 * Targets: DES key setup, encryption/decryption operations, and various DES modes
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/des.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check - need enough data for keys, IVs, and operation parameters
    if (size < 32) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Initialize OpenSSL library
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();

    // Consume operation type to decide which DES test to run
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 10;
    
    switch (operation) {
        case 0: {
            // Test DES key setup and basic operations
            DES_cblock key;
            if (fdp.remaining_bytes() < sizeof(DES_cblock)) {
                return 0;
            }
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            
            // Test various key setup functions
            uint8_t key_setup_op = fdp.ConsumeIntegral<uint8_t>() % 4;
            switch (key_setup_op) {
                case 0:
                    DES_set_key(&key, &schedule);
                    break;
                case 1:
                    DES_key_sched(&key, &schedule);
                    break;
                case 2:
                    DES_set_key_checked(&key, &schedule);
                    break;
                case 3:
                    DES_set_key_unchecked(&key, &schedule);
                    break;
            }
            
            // Test key parity functions
            DES_set_odd_parity(&key);
            DES_check_key_parity(&key);
            DES_is_weak_key(&key);
            
            break;
        }
        
        case 1: {
            // Test DES ECB encryption/decryption
            DES_cblock key, input, output;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 2) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto input_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            memcpy(input, input_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Test both encryption and decryption
            int enc = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
            DES_ecb_encrypt(&input, &output, &schedule, enc);
            
            break;
        }
        
        case 2: {
            // Test DES CBC encryption/decryption
            DES_cblock key, iv;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 2) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto iv_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            memcpy(iv, iv_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Consume data for encryption
            size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
            if (fdp.remaining_bytes() < data_len) {
                return 0;
            }
            
            std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(data_len);
            std::vector<uint8_t> output_data(data_len);
            
            int enc = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
            
            // Test different CBC variants
            uint8_t cbc_variant = fdp.ConsumeIntegral<uint8_t>() % 3;
            switch (cbc_variant) {
                case 0:
                    DES_cbc_encrypt(input_data.data(), output_data.data(), data_len,
                                   &schedule, &iv, enc);
                    break;
                case 1:
                    DES_ncbc_encrypt(input_data.data(), output_data.data(), data_len,
                                    &schedule, &iv, enc);
                    break;
                case 2:
                    // DES_xcbc_encrypt needs inw and outw parameters
                    DES_cblock inw, outw;
                    if (fdp.remaining_bytes() >= sizeof(DES_cblock) * 2) {
                        auto inw_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                        auto outw_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                        memcpy(inw, inw_bytes.data(), sizeof(DES_cblock));
                        memcpy(outw, outw_bytes.data(), sizeof(DES_cblock));
                        DES_xcbc_encrypt(input_data.data(), output_data.data(), data_len,
                                        &schedule, &iv, &inw, &outw, enc);
                    }
                    break;
            }
            
            break;
        }
        
        case 3: {
            // Test DES CFB encryption/decryption
            DES_cblock key, iv;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 2) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto iv_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            memcpy(iv, iv_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Consume data for encryption
            size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
            if (fdp.remaining_bytes() < data_len) {
                return 0;
            }
            
            std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(data_len);
            std::vector<uint8_t> output_data(data_len);
            
            int enc = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
            int num = fdp.ConsumeIntegral<int>() & 0x07; // CFB position (0-7)
            
            // Test different CFB variants
            uint8_t cfb_variant = fdp.ConsumeIntegral<uint8_t>() % 3;
            switch (cfb_variant) {
                case 0:
                    DES_cfb64_encrypt(input_data.data(), output_data.data(), data_len,
                                     &schedule, &iv, &num, enc);
                    break;
                case 1:
                    DES_cfb_encrypt(input_data.data(), output_data.data(),
                                   fdp.ConsumeIntegralInRange<int>(1, 64),
                                   data_len, &schedule, &iv, enc);
                    break;
                case 2:
                    if (fdp.remaining_bytes() >= 2 * sizeof(DES_cblock)) {
                        DES_cblock key2, key3;
                        auto key2_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                        auto key3_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                        memcpy(key2, key2_bytes.data(), sizeof(DES_cblock));
                        memcpy(key3, key3_bytes.data(), sizeof(DES_cblock));
                        
                        DES_key_schedule schedule2, schedule3;
                        DES_set_key_unchecked(&key2, &schedule2);
                        DES_set_key_unchecked(&key3, &schedule3);
                        
                        DES_ede3_cfb64_encrypt(input_data.data(), output_data.data(),
                                              data_len, &schedule, &schedule2, &schedule3,
                                              &iv, &num, enc);
                    }
                    break;
            }
            
            break;
        }
        
        case 4: {
            // Test DES OFB encryption
            DES_cblock key, iv;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 2) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto iv_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            memcpy(iv, iv_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Consume data for encryption
            size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
            if (fdp.remaining_bytes() < data_len) {
                return 0;
            }
            
            std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(data_len);
            std::vector<uint8_t> output_data(data_len);
            
            int num = fdp.ConsumeIntegral<int>() & 0x07; // OFB position (0-7)
            
            // Test different OFB variants
            uint8_t ofb_variant = fdp.ConsumeIntegral<uint8_t>() % 3;
            switch (ofb_variant) {
                case 0:
                    DES_ofb64_encrypt(input_data.data(), output_data.data(), data_len,
                                     &schedule, &iv, &num);
                    break;
                case 1:
                    DES_ofb_encrypt(input_data.data(), output_data.data(),
                                   fdp.ConsumeIntegralInRange<int>(1, 64),
                                   data_len, &schedule, &iv);
                    break;
                case 2:
                    if (fdp.remaining_bytes() >= 2 * sizeof(DES_cblock)) {
                        DES_cblock key2, key3;
                        auto key2_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                        auto key3_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                        memcpy(key2, key2_bytes.data(), sizeof(DES_cblock));
                        memcpy(key3, key3_bytes.data(), sizeof(DES_cblock));
                        
                        DES_key_schedule schedule2, schedule3;
                        DES_set_key_unchecked(&key2, &schedule2);
                        DES_set_key_unchecked(&key3, &schedule3);
                        
                        DES_ede3_ofb64_encrypt(input_data.data(), output_data.data(),
                                              data_len, &schedule, &schedule2, &schedule3,
                                              &iv, &num);
                    }
                    break;
            }
            
            break;
        }
        
        case 5: {
            // Test DES PCBC encryption/decryption
            DES_cblock key, iv;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 2) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto iv_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            memcpy(iv, iv_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Consume data for encryption
            size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
            if (fdp.remaining_bytes() < data_len) {
                return 0;
            }
            
            std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(data_len);
            std::vector<uint8_t> output_data(data_len);
            
            int enc = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
            
            DES_pcbc_encrypt(input_data.data(), output_data.data(), data_len,
                           &schedule, &iv, enc);
            
            break;
        }
        
        case 6: {
            // Test triple DES (3DES) operations
            DES_cblock key1, key2, key3, iv;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 4) {
                return 0;
            }
            
            auto key1_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto key2_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto key3_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto iv_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key1, key1_bytes.data(), sizeof(DES_cblock));
            memcpy(key2, key2_bytes.data(), sizeof(DES_cblock));
            memcpy(key3, key3_bytes.data(), sizeof(DES_cblock));
            memcpy(iv, iv_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule1, schedule2, schedule3;
            DES_set_key_unchecked(&key1, &schedule1);
            DES_set_key_unchecked(&key2, &schedule2);
            DES_set_key_unchecked(&key3, &schedule3);
            
            // Consume data for encryption
            size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
            if (fdp.remaining_bytes() < data_len) {
                return 0;
            }
            
            std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(data_len);
            std::vector<uint8_t> output_data(data_len);
            
            int enc = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
            
            // Test 3DES CBC
            DES_ede3_cbc_encrypt(input_data.data(), output_data.data(), data_len,
                               &schedule1, &schedule2, &schedule3, &iv, enc);
            
            break;
        }
        
        case 7: {
            // Test DES checksum functions
            DES_cblock key, seed, output[4];
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock) * 2) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            auto seed_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            memcpy(seed, seed_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Consume data for checksum
            size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 256);
            if (fdp.remaining_bytes() < data_len) {
                return 0;
            }
            
            std::vector<uint8_t> input_data = fdp.ConsumeBytes<uint8_t>(data_len);
            
            // Test DES_cbc_cksum
            DES_cblock cksum_result;
            DES_cbc_cksum(input_data.data(), &cksum_result, data_len,
                         &schedule, &seed);
            
            // Test DES_quad_cksum
            int out_count = fdp.ConsumeIntegralInRange<int>(1, 4);
            DES_quad_cksum(input_data.data(), output, data_len,
                          out_count, &seed);
            
            break;
        }
        
        case 8: {
            // Test DES string functions
            std::string buf = fdp.ConsumeRandomLengthString(256);
            std::string salt = fdp.ConsumeRandomLengthString(2);
            
            if (salt.length() < 2) {
                // Ensure salt is at least 2 chars for DES_crypt
                salt = "aa";
            }
            
            // Test DES_crypt
            char* crypt_result = DES_crypt(buf.c_str(), salt.c_str());
            
            // Test DES_fcrypt
            char ret[14]; // DES_fcrypt output buffer
            DES_fcrypt(buf.c_str(), salt.c_str(), ret);
            
            // Test DES_string_to_key and DES_string_to_2keys
            DES_cblock key1, key2;
            DES_string_to_key(buf.c_str(), &key1);
            
            if (fdp.remaining_bytes() > 0) {
                std::string str2 = fdp.ConsumeRandomLengthString(256);
                DES_string_to_2keys(str2.c_str(), &key1, &key2);
            }
            
            break;
        }
        
        case 9: {
            // Test DES low-level encryption functions
            DES_cblock key;
            
            if (fdp.remaining_bytes() < sizeof(DES_cblock)) {
                return 0;
            }
            
            auto key_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
            memcpy(key, key_bytes.data(), sizeof(DES_cblock));
            
            DES_key_schedule schedule;
            DES_set_key_unchecked(&key, &schedule);
            
            // Prepare data for low-level encryption
            DES_LONG data[2];
            if (fdp.remaining_bytes() >= sizeof(DES_LONG) * 2) {
                data[0] = fdp.ConsumeIntegral<DES_LONG>();
                data[1] = fdp.ConsumeIntegral<DES_LONG>();
                
                int enc = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
                
                // Test low-level encryption functions
                DES_encrypt1(data, &schedule, enc);
                
                // Reset data for additional tests
                if (fdp.remaining_bytes() >= sizeof(DES_LONG) * 2) {
                    data[0] = fdp.ConsumeIntegral<DES_LONG>();
                    data[1] = fdp.ConsumeIntegral<DES_LONG>();
                    DES_encrypt2(data, &schedule, enc);
                }
            }
            
            // Test 3DES low-level functions
            if (fdp.remaining_bytes() >= 3 * sizeof(DES_cblock)) {
                DES_cblock key2, key3;
                auto key2_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                auto key3_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(DES_cblock));
                
                memcpy(key2, key2_bytes.data(), sizeof(DES_cblock));
                memcpy(key3, key3_bytes.data(), sizeof(DES_cblock));
                
                DES_key_schedule schedule2, schedule3;
                DES_set_key_unchecked(&key2, &schedule2);
                DES_set_key_unchecked(&key3, &schedule3);
                
                if (fdp.remaining_bytes() >= sizeof(DES_LONG) * 2) {
                    DES_LONG data3[2];
                    data3[0] = fdp.ConsumeIntegral<DES_LONG>();
                    data3[1] = fdp.ConsumeIntegral<DES_LONG>();
                    
                    int enc3 = fdp.ConsumeBool() ? DES_ENCRYPT : DES_DECRYPT;
                    if (enc3 == DES_ENCRYPT) {
                        DES_encrypt3(data3, &schedule, &schedule2, &schedule3);
                    } else {
                        DES_decrypt3(data3, &schedule, &schedule2, &schedule3);
                    }
                }
            }
            
            break;
        }
    }
    
    // Clear any accumulated errors
    ERR_clear_error();
    
    return 0;
}
