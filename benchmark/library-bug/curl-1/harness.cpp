#include <curl/curl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check
    if (size < 4) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Initialize curl
    CURL* curl = curl_easy_init();
    if (!curl) {
        return 0;
    }
    
    // Consume a URL from input
    std::string url = fdp.ConsumeRandomLengthString(256);
    
    // Set basic options - avoid options that trigger optional dependencies
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // Set timeout
    long timeout = fdp.ConsumeIntegralInRange<long>(0, 10);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    
    // Set verbosity based on input
    bool verbose = fdp.ConsumeBool();
    curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose ? 1L : 0L);
    
    // Set follow location
    bool follow_location = fdp.ConsumeBool();
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, follow_location ? 1L : 0L);
    
    // Set max redirects
    long max_redirects = fdp.ConsumeIntegralInRange<long>(0, 10);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, max_redirects);
    
    // Set connection timeout
    long connect_timeout = fdp.ConsumeIntegralInRange<long>(0, 10);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
    
    // Set TCP no delay
    bool tcp_no_delay = fdp.ConsumeBool();
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, tcp_no_delay ? 1L : 0L);
    
    // Set HTTP method - only GET to avoid POST dependencies
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    
    // Set write function to discard response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, 
        [](void* buffer, size_t size, size_t nmemb, void* userp) -> size_t {
            return size * nmemb;
        });
    
    // Try to perform (will likely fail due to invalid URL, but that's OK for fuzzing)
    CURLcode res = curl_easy_perform(curl);
    
    // Clean up
    curl_easy_cleanup(curl);
    
    return 0;
}
