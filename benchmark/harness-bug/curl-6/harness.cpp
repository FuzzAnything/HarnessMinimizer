// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_url_get at urlapi.c:1541:11 in urlapi.h
// curl_free at escape.c:189:6 in curl.h
// curl_url_get at urlapi.c:1541:11 in urlapi.h
// curl_free at escape.c:189:6 in curl.h
// curl_url_get at urlapi.c:1541:11 in urlapi.h
// curl_free at escape.c:189:6 in curl.h
// curl_url_get at urlapi.c:1541:11 in urlapi.h
// curl_free at escape.c:189:6 in curl.h
// curl_url_dup at urlapi.c:1310:8 in urlapi.h
// curl_url_get at urlapi.c:1541:11 in urlapi.h
// curl_free at escape.c:189:6 in curl.h
// curl_url_cleanup at urlapi.c:1293:6 in urlapi.h
// curl_url_cleanup at urlapi.c:1293:6 in urlapi.h
// curl_url_cleanup at urlapi.c:1293:6 in urlapi.h
// curl_url_dup at urlapi.c:1310:8 in urlapi.h
// curl_url_cleanup at urlapi.c:1293:6 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url_strerror at strerror.c:420:13 in urlapi.h
// curl_url at urlapi.c:1288:8 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_set at urlapi.c:1805:11 in urlapi.h
// curl_url_get at urlapi.c:1541:11 in urlapi.h
// curl_free at escape.c:189:6 in curl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "curl/curl.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void dummy_cleanup(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create a dummy file if needed (not used directly by URL API functions)
    FILE *dummy = fopen("./dummy_file", "wb");
    if (dummy) {
        if (Size > 0) {
            fwrite(Data, 1, Size, dummy);
        }
        fclose(dummy);
    }

    // Test curl_url_strerror with various error codes
    const char *err_str = curl_url_strerror(CURLUE_OK);
    err_str = curl_url_strerror(CURLUE_BAD_HANDLE);
    err_str = curl_url_strerror(CURLUE_BAD_PARTPOINTER);
    err_str = curl_url_strerror(CURLUE_MALFORMED_INPUT);
    err_str = curl_url_strerror(CURLUE_BAD_PORT_NUMBER);
    err_str = curl_url_strerror(CURLUE_UNSUPPORTED_SCHEME);
    err_str = curl_url_strerror(CURLUE_URLDECODE);
    err_str = curl_url_strerror(CURLUE_OUT_OF_MEMORY);
    err_str = curl_url_strerror(CURLUE_USER_NOT_ALLOWED);
    err_str = curl_url_strerror(CURLUE_UNKNOWN_PART);
    err_str = curl_url_strerror(CURLUE_NO_SCHEME);
    err_str = curl_url_strerror(CURLUE_NO_USER);
    err_str = curl_url_strerror(CURLUE_NO_PASSWORD);
    err_str = curl_url_strerror(CURLUE_NO_OPTIONS);
    err_str = curl_url_strerror(CURLUE_NO_HOST);
    err_str = curl_url_strerror(CURLUE_NO_PORT);
    err_str = curl_url_strerror(CURLUE_NO_QUERY);
    err_str = curl_url_strerror(CURLUE_NO_FRAGMENT);
    err_str = curl_url_strerror(CURLUE_NO_ZONEID);
    err_str = curl_url_strerror((CURLUcode)(Data[0] % 30)); // Random error code

    // Test curl_url() - create a new handle
    CURLU *url = curl_url();
    if (!url) {
        return 0;
    }

    // Test curl_url_set() with various parts using fuzzer data
    // We'll use the fuzzer input to create strings for different parts
    char *temp_str = NULL;
    if (Size > 0) {
        temp_str = (char *)malloc(Size + 1);
        if (temp_str) {
            memcpy(temp_str, Data, Size);
            temp_str[Size] = '\0';
            
            // Try setting different URL parts with the fuzzer data
            curl_url_set(url, CURLUPART_SCHEME, "http", 0);
            curl_url_set(url, CURLUPART_HOST, temp_str, 0);
            curl_url_set(url, CURLUPART_PATH, temp_str, 0);
            curl_url_set(url, CURLUPART_QUERY, temp_str, 0);
            curl_url_set(url, CURLUPART_FRAGMENT, temp_str, 0);
            curl_url_set(url, CURLUPART_USER, temp_str, 0);
            curl_url_set(url, CURLUPART_PASSWORD, temp_str, 0);
            curl_url_set(url, CURLUPART_PORT, "80", 0);
            
            // Try with flags
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_NON_SUPPORT_SCHEME);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_URLENCODE);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_URLDECODE);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_DEFAULT_SCHEME);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_GUESS_SCHEME);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_NO_AUTHORITY);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_PATH_AS_IS);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_DISALLOW_USER);
            curl_url_set(url, CURLUPART_URL, temp_str, CURLU_APPENDQUERY);
            
            // Clear some parts
            curl_url_set(url, CURLUPART_QUERY, NULL, 0);
            curl_url_set(url, CURLUPART_FRAGMENT, NULL, 0);
            
            free(temp_str);
        }
    }

    // Test curl_url_get() to retrieve various parts
    char *retrieved_part = NULL;
    
    curl_url_get(url, CURLUPART_SCHEME, &retrieved_part, 0);
    if (retrieved_part) {
        curl_free(retrieved_part);
        retrieved_part = NULL;
    }
    
    curl_url_get(url, CURLUPART_HOST, &retrieved_part, 0);
    if (retrieved_part) {
        curl_free(retrieved_part);
        retrieved_part = NULL;
    }
    
    curl_url_get(url, CURLUPART_PATH, &retrieved_part, 0);
    if (retrieved_part) {
        curl_free(retrieved_part);
        retrieved_part = NULL;
    }
    
    curl_url_get(url, CURLUPART_URL, &retrieved_part, 0);
    if (retrieved_part) {
        curl_free(retrieved_part);
        retrieved_part = NULL;
    }
    
    // Test with decoding flag
    curl_url_get(url, CURLUPART_URL, &retrieved_part, CURLU_URLDECODE);
    if (retrieved_part) {
        curl_free(retrieved_part);
        retrieved_part = NULL;
    }

    // Test curl_url_dup() - duplicate the handle
    CURLU *url_copy = curl_url_dup(url);
    if (url_copy) {
        // Test operations on the copy
        curl_url_get(url_copy, CURLUPART_URL, &retrieved_part, 0);
        if (retrieved_part) {
            curl_free(retrieved_part);
            retrieved_part = NULL;
        }
        
        // Clean up the copy
        curl_url_cleanup(url_copy);
    }

    // Clean up the original handle
    curl_url_cleanup(url);

    // Test edge cases
    // Test with NULL handle for curl_url_cleanup
    curl_url_cleanup(NULL);
    
    // Test curl_url_dup with NULL
    CURLU *null_copy = curl_url_dup(NULL);
    if (null_copy) {
        curl_url_cleanup(null_copy);
    }

    return 0;
}
