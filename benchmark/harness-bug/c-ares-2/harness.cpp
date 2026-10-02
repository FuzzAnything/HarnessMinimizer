/* Fuzzing harness for c-ares library targeting DNS record resource record manipulation functions
 * This harness tests DNS record data manipulation with binary, string, and address data types
 * Target APIs: ares_dns_rr_set_bin, ares_dns_rr_add_abin, ares_dns_rr_set_str, ares_dns_rr_del_abin,
 *              ares_dns_rr_get_bin, ares_dns_rr_get_str, ares_dns_rr_get_abin, ares_dns_rr_get_addr,
 *              ares_dns_rr_get_addr6, ares_dns_rr_get_u32, ares_dns_rr_get_abin_cnt
 * Helper APIs: ares_dns_record_create, ares_dns_record_rr_add, ares_dns_record_destroy,
 *              ares_dns_rr_set_addr, ares_dns_rr_set_addr6, ares_dns_rr_set_u32
 * Follows exact invocation sequence from coverage guidance
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>

#include "ares.h"
#include "ares_dns.h"
#include "ares_dns_record.h"
#include "ares_nameser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check for meaningful fuzzing
    // We need enough data for: record creation + RR addition + binary/string/address data
    if (size < 100) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Initialize library
    ares_library_init(ARES_LIB_INIT_ALL);

    // 1. Call ares_dns_record_create to create a new DNS record
    ares_dns_record_t* dnsrec = NULL;
    ares_status_t status = ares_dns_record_create(&dnsrec, 
                                                  fdp.ConsumeIntegral<unsigned short>(),  // id
                                                  fdp.ConsumeIntegral<unsigned short>(),  // flags
                                                  (ares_dns_opcode_t)(fdp.ConsumeIntegral<uint8_t>() % 6),  // opcode
                                                  (ares_dns_rcode_t)(fdp.ConsumeIntegral<uint8_t>() % 16)); // rcode
    if (status != ARES_SUCCESS || dnsrec == NULL) {
        ares_library_cleanup();
        return 0;
    }

    // 2. Call ares_dns_record_rr_add to add a resource record to the record
    // Choose a record type that supports various data types
    ares_dns_rr_t* rr = NULL;
    status = ares_dns_record_rr_add(&rr, dnsrec, 
                                    ARES_SECTION_ANSWER,
                                    fdp.ConsumeRandomLengthString(64).c_str(),  // name
                                    ARES_REC_TYPE_TLSA,  // TLSA supports binary data
                                    ARES_CLASS_IN,
                                    fdp.ConsumeIntegral<unsigned int>());  // ttl
    
    if (status != ARES_SUCCESS || rr == NULL) {
        ares_dns_record_destroy(dnsrec);
        ares_library_cleanup();
        return 0;
    }

    // 3. Call ares_dns_rr_set_bin to set binary data on the RR
    if (fdp.remaining_bytes() >= 32) {
        size_t bin_len = fdp.ConsumeIntegralInRange<size_t>(1, 64);
        std::vector<uint8_t> bin_data = fdp.ConsumeBytes<uint8_t>(bin_len);
        
        status = ares_dns_rr_set_bin(rr, ARES_RR_TLSA_DATA, 
                                     bin_data.data(), bin_data.size());
        // Don't fail on error - continue testing other APIs
    }

    // 4. Call ares_dns_rr_get_bin to retrieve and verify the binary data
    if (rr != NULL) {
        size_t get_len = 0;
        const unsigned char* get_bin = ares_dns_rr_get_bin(rr, ARES_RR_TLSA_DATA, &get_len);
        // Just retrieve - no need to verify
        (void)get_bin;
        (void)get_len;
    }

    // For ABINP testing, we need a different record type - let's add another RR
    ares_dns_rr_t* rr2 = NULL;
    if (fdp.remaining_bytes() > 20) {
        // Add a TXT record which uses ABINP datatype for TXT strings
        status = ares_dns_record_rr_add(&rr2, dnsrec,
                                        ARES_SECTION_ANSWER,
                                        fdp.ConsumeRandomLengthString(64).c_str(),
                                        ARES_REC_TYPE_TXT,
                                        ARES_CLASS_IN,
                                        fdp.ConsumeIntegral<unsigned int>());
        
        if (status == ARES_SUCCESS && rr2 != NULL) {
            // 5. Call ares_dns_rr_add_abin to add additional binary data
            // TXT records have ARES_RR_TXT_DATA which is ABINP datatype
            for (int i = 0; i < 3 && fdp.remaining_bytes() > 10; i++) {
                size_t abin_len = fdp.ConsumeIntegralInRange<size_t>(1, 32);
                std::vector<uint8_t> abin_data = fdp.ConsumeBytes<uint8_t>(abin_len);
                
                status = ares_dns_rr_add_abin(rr2, ARES_RR_TXT_DATA,
                                              abin_data.data(), abin_data.size());
                // Continue regardless of success
            }

            // 6. Call ares_dns_rr_get_abin to retrieve the added binary data
            // 7. Call ares_dns_rr_get_abin_cnt to count binary entries
            if (rr2 != NULL) {
                size_t abin_cnt = ares_dns_rr_get_abin_cnt(rr2, ARES_RR_TXT_DATA);
                for (size_t i = 0; i < abin_cnt && i < 5; i++) {
                    size_t elem_len = 0;
                    const unsigned char* elem_data = ares_dns_rr_get_abin(rr2, ARES_RR_TXT_DATA, i, &elem_len);
                    (void)elem_data;
                    (void)elem_len;
                }
            }
        }
    }

    // 8. Call ares_dns_rr_set_str to set string data
    // Add a SIG record for string testing
    ares_dns_rr_t* rr3 = NULL;
    if (fdp.remaining_bytes() > 20) {
        status = ares_dns_record_rr_add(&rr3, dnsrec,
                                        ARES_SECTION_ANSWER,
                                        fdp.ConsumeRandomLengthString(64).c_str(),
                                        ARES_REC_TYPE_SIG,
                                        ARES_CLASS_IN,
                                        fdp.ConsumeIntegral<unsigned int>());
        
        if (status == ARES_SUCCESS && rr3 != NULL) {
            // Set various string fields on SIG record
            std::string signer_name = fdp.ConsumeRandomLengthString(128);
            status = ares_dns_rr_set_str(rr3, ARES_RR_SIG_SIGNERS_NAME, signer_name.c_str());
            
            // 9. Call ares_dns_rr_get_str to retrieve string data
            const char* retrieved_str = ares_dns_rr_get_str(rr3, ARES_RR_SIG_SIGNERS_NAME);
            (void)retrieved_str;
        }
    }

    // 10. Call ares_dns_rr_set_addr/ares_dns_rr_set_addr6/ares_dns_rr_set_u32 
    //     to set address/numeric data
    // Add A and AAAA records for address testing
    ares_dns_rr_t* rr4 = NULL;
    if (fdp.remaining_bytes() > 20) {
        // A record (IPv4)
        status = ares_dns_record_rr_add(&rr4, dnsrec,
                                        ARES_SECTION_ANSWER,
                                        fdp.ConsumeRandomLengthString(64).c_str(),
                                        ARES_REC_TYPE_A,
                                        ARES_CLASS_IN,
                                        fdp.ConsumeIntegral<unsigned int>());
        
        if (status == ARES_SUCCESS && rr4 != NULL) {
            // Set IPv4 address
            struct in_addr ipv4_addr;
            if (fdp.remaining_bytes() >= sizeof(struct in_addr)) {
                std::vector<uint8_t> addr_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(struct in_addr));
                memcpy(&ipv4_addr, addr_bytes.data(), sizeof(struct in_addr));
                status = ares_dns_rr_set_addr(rr4, ARES_RR_A_ADDR, &ipv4_addr);
            }
        }
    }

    ares_dns_rr_t* rr5 = NULL;
    if (fdp.remaining_bytes() > 20) {
        // AAAA record (IPv6)
        status = ares_dns_record_rr_add(&rr5, dnsrec,
                                        ARES_SECTION_ANSWER,
                                        fdp.ConsumeRandomLengthString(64).c_str(),
                                        ARES_REC_TYPE_AAAA,
                                        ARES_CLASS_IN,
                                        fdp.ConsumeIntegral<unsigned int>());
        
        if (status == ARES_SUCCESS && rr5 != NULL) {
            // Set IPv6 address
            struct ares_in6_addr ipv6_addr;
            if (fdp.remaining_bytes() >= sizeof(struct ares_in6_addr)) {
                std::vector<uint8_t> addr6_bytes = fdp.ConsumeBytes<uint8_t>(sizeof(struct ares_in6_addr));
                memcpy(&ipv6_addr, addr6_bytes.data(), sizeof(struct ares_in6_addr));
                status = ares_dns_rr_set_addr6(rr5, ARES_RR_AAAA_ADDR, &ipv6_addr);
            }
        }
    }

    // Add a record with U32 field
    ares_dns_rr_t* rr6 = NULL;
    if (fdp.remaining_bytes() > 20) {
        // SOA record has U32 fields
        status = ares_dns_record_rr_add(&rr6, dnsrec,
                                        ARES_SECTION_AUTHORITY,
                                        fdp.ConsumeRandomLengthString(64).c_str(),
                                        ARES_REC_TYPE_SOA,
                                        ARES_CLASS_IN,
                                        fdp.ConsumeIntegral<unsigned int>());
        
        if (status == ARES_SUCCESS && rr6 != NULL) {
            // Set U32 fields
            unsigned int serial = fdp.ConsumeIntegral<unsigned int>();
            status = ares_dns_rr_set_u32(rr6, ARES_RR_SOA_SERIAL, serial);
            
            unsigned int refresh = fdp.ConsumeIntegral<unsigned int>();
            status = ares_dns_rr_set_u32(rr6, ARES_RR_SOA_REFRESH, refresh);
            
            unsigned int retry = fdp.ConsumeIntegral<unsigned int>();
            status = ares_dns_rr_set_u32(rr6, ARES_RR_SOA_RETRY, retry);
            
            unsigned int expire = fdp.ConsumeIntegral<unsigned int>();
            status = ares_dns_rr_set_u32(rr6, ARES_RR_SOA_EXPIRE, expire);
            
            unsigned int minimum = fdp.ConsumeIntegral<unsigned int>();
            status = ares_dns_rr_set_u32(rr6, ARES_RR_SOA_MINIMUM, minimum);
        }
    }

    // 11. Call ares_dns_rr_get_addr/ares_dns_rr_get_addr6/ares_dns_rr_get_u32 
    //     to retrieve address/numeric data
    if (rr4 != NULL) {
        const struct in_addr* get_ipv4 = ares_dns_rr_get_addr(rr4, ARES_RR_A_ADDR);
        (void)get_ipv4;
    }
    
    if (rr5 != NULL) {
        const struct ares_in6_addr* get_ipv6 = ares_dns_rr_get_addr6(rr5, ARES_RR_AAAA_ADDR);
        (void)get_ipv6;
    }
    
    if (rr6 != NULL) {
        unsigned int get_serial = ares_dns_rr_get_u32(rr6, ARES_RR_SOA_SERIAL);
        unsigned int get_refresh = ares_dns_rr_get_u32(rr6, ARES_RR_SOA_REFRESH);
        unsigned int get_retry = ares_dns_rr_get_u32(rr6, ARES_RR_SOA_RETRY);
        unsigned int get_expire = ares_dns_rr_get_u32(rr6, ARES_RR_SOA_EXPIRE);
        unsigned int get_minimum = ares_dns_rr_get_u32(rr6, ARES_RR_SOA_MINIMUM);
        (void)get_serial;
        (void)get_refresh;
        (void)get_retry;
        (void)get_expire;
        (void)get_minimum;
    }

    // 12. Call ares_dns_rr_del_abin to delete binary data
    if (rr2 != NULL) {
        size_t abin_cnt = ares_dns_rr_get_abin_cnt(rr2, ARES_RR_TXT_DATA);
        if (abin_cnt > 0) {
            // Delete first element if it exists
            status = ares_dns_rr_del_abin(rr2, ARES_RR_TXT_DATA, 0);
        }
    }

    // 13. Call ares_dns_record_destroy to clean up the record
    ares_dns_record_destroy(dnsrec);

    // Cleanup library
    ares_library_cleanup();

    return 0;
}
