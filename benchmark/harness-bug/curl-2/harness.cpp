#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>
#include <curl/curl.h>

// Header callback function to capture headers during transfer
static size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    // Simply return the size to indicate we processed the header
    // In real usage, we might store headers, but for fuzzing we just want to populate them
    return size * nitems;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum input size check: need enough for configuration and header iteration
    if (size < 32) {
        return 0; // Need minimum input for meaningful header testing
    }

    FuzzedDataProvider fdp(data, size);

    // Step 1: Initialize curl globally
    CURLcode global_result = curl_global_init(CURL_GLOBAL_ALL);
    if (global_result != CURLE_OK) {
        return 0;
    }

    // Step 2: Create curl easy handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0;
    }

    // Step 3: Consume URL from fuzzer input
    std::string url = fdp.ConsumeRandomLengthString(256);
    if (url.empty()) {
        // Use a dummy URL if input doesn't provide one
        url = "http://localhost/";
    }

    // Set the URL
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Step 4: Set header callback to capture headers
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, nullptr);

    // Step 5: Set write callback (though we won't actually write data)
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, nullptr);

    // Step 6: Set options to prevent actual network connection
    // Use very short timeouts to avoid hanging
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 10L);
    
    // Disable signal handling for fuzzing safety
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    // Don't follow redirects to simplify testing
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    // Step 7: Attempt to perform the request (will likely fail due to no network)
    // This is okay - we want to test the header API functions even without actual headers
    CURLcode perform_result = curl_easy_perform(curl);
    (void)perform_result; // Result may be CURLE_OK or error

    // Step 8: Primary target API: curl_easy_header
    // Try to get specific header types using fuzzed input
    
    // Consume header name to search for
    std::string target_header_name = fdp.ConsumeRandomLengthString(50);
    
    // Consume header type (CURLH_HEADER, CURLH_TRAILER, CURLH_CONNECT, CURLH_1XX, CURLH_PSEUDO)
    uint8_t header_type_choice = fdp.ConsumeIntegral<uint8_t>() % 5;
    int header_type = CURLH_HEADER;
    switch (header_type_choice) {
        case 0: header_type = CURLH_HEADER; break;
        case 1: header_type = CURLH_TRAILER; break;
        case 2: header_type = CURLH_CONNECT; break;
        case 3: header_type = CURLH_1XX; break;
        case 4: header_type = CURLH_PSEUDO; break;
    }
    
    // Consume index (0 = first occurrence, -1 = last occurrence, N = Nth occurrence)
    int index = fdp.ConsumeIntegralInRange<int>(-10, 10);
    
    struct curl_header* header = nullptr;
    
    // Try to get the specific header
    CURLHcode header_result = curl_easy_header(curl, 
                                               target_header_name.empty() ? nullptr : target_header_name.c_str(),
                                               0,  // 0 = case-sensitive match
                                               header_type,
                                               index,
                                               &header);
    
    // Step 9: Primary target API: curl_easy_nextheader (highest value with 34 undiscovered branches)
    // Test iteration through headers using different iteration strategies
    
    // Strategy 1: Iterate through all headers of a specific type
    struct curl_header* prev_header = nullptr;
    uint8_t iteration_type = fdp.ConsumeIntegral<uint8_t>() % 3;
    
    switch (iteration_type) {
        case 0: {
            // Iterate through all headers
            do {
                prev_header = curl_easy_nextheader(curl, CURLH_HEADER, -1, prev_header);
            } while (prev_header != nullptr && fdp.ConsumeBool());
            break;
        }
        case 1: {
            // Iterate through trailers
            do {
                prev_header = curl_easy_nextheader(curl, CURLH_TRAILER, -1, prev_header);
            } while (prev_header != nullptr && fdp.ConsumeBool());
            break;
        }
        case 2: {
            // Iterate through all header types with varying index
            int iter_index = fdp.ConsumeIntegralInRange<int>(-5, 5);
            uint8_t iter_header_type = fdp.ConsumeIntegral<uint8_t>() % 5;
            int actual_header_type = CURLH_HEADER;
            switch (iter_header_type) {
                case 0: actual_header_type = CURLH_HEADER; break;
                case 1: actual_header_type = CURLH_TRAILER; break;
                case 2: actual_header_type = CURLH_CONNECT; break;
                case 3: actual_header_type = CURLH_1XX; break;
                case 4: actual_header_type = CURLH_PSEUDO; break;
            }
            
            struct curl_header* iter_prev = nullptr;
            do {
                iter_prev = curl_easy_nextheader(curl, actual_header_type, iter_index, iter_prev);
            } while (iter_prev != nullptr && fdp.ConsumeBool());
            break;
        }
    }
    
    // Step 10: Test edge cases and error paths
    
    // Test with null curl handle (should handle gracefully in API)
    if (fdp.ConsumeBool()) {
        struct curl_header* dummy_header = nullptr;
        CURLHcode null_result = curl_easy_header(nullptr, "Content-Type", 0, CURLH_HEADER, 0, &dummy_header);
        (void)null_result;
        
        struct curl_header* null_next = curl_easy_nextheader(nullptr, CURLH_HEADER, -1, nullptr);
        (void)null_next;
    }
    
    // Test with invalid header types
    if (fdp.ConsumeBool()) {
        struct curl_header* invalid_header = nullptr;
        CURLHcode invalid_result = curl_easy_header(curl, "Invalid-Header", 0, 999, 0, &invalid_header);
        (void)invalid_result;
        
        struct curl_header* invalid_next = curl_easy_nextheader(curl, 999, -1, nullptr);
        (void)invalid_next;
    }
    
    // Test header amount and other header structure fields
    if (header != nullptr) {
        // Access header structure fields to ensure they're exercised
        const char* name = header->name;
        const char* value = header->value;
        size_t amount = header->amount;
        size_t index_val = header->index;
        unsigned int origin = header->origin;
        (void)name;
        (void)value;
        (void)amount;
        (void)index_val;
        (void)origin;
    }
    
    // Step 11: Cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}
