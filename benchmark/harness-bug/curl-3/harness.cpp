// This fuzz driver is generated for library curl, aiming to fuzz the following functions:
// curl_multi_poll at multi.c:1584:11 in multi.h
// curl_multi_init at multi.c:335:8 in multi.h
// curl_multi_timeout at multi.c:3394:11 in multi.h
// curl_multi_perform at multi.c:2829:11 in multi.h
// curl_multi_cleanup at multi.c:2839:11 in multi.h
// curl_multi_socket_action at multi.c:3291:11 in multi.h
// curl_multi_get_offt at multi.c:3747:11 in multi.h
// curl_multi_wait at multi.c:1574:11 in multi.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define CURL_DISABLE_TYPECHECK
#include "curl/multi.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    // Use first byte to decide which function to call
    if (Size > 0) {
        uint8_t selector = Data[0] % 6;
        Data++;
        Size--;

        switch (selector) {
            case 0: {
                // curl_multi_socket_action
                curl_socket_t s = -1;
                int ev_bitmask = 0;
                int running_handles = 0;
                
                if (Size >= sizeof(curl_socket_t)) {
                    memcpy(&s, Data, sizeof(curl_socket_t));
                    Data += sizeof(curl_socket_t);
                    Size -= sizeof(curl_socket_t);
                }
                if (Size >= sizeof(int)) {
                    memcpy(&ev_bitmask, Data, sizeof(int));
                }
                
                curl_multi_socket_action(multi_handle, s, ev_bitmask, &running_handles);
                break;
            }
            
            case 1: {
                // curl_multi_get_offt
                CURLMinfo_offt info = CURLMINFO_XFERS_RUNNING;
                curl_off_t value = 0;
                
                if (Size >= sizeof(CURLMinfo_offt)) {
                    memcpy(&info, Data, sizeof(CURLMinfo_offt));
                    Data += sizeof(CURLMinfo_offt);
                    Size -= sizeof(CURLMinfo_offt);
                }
                
                curl_multi_get_offt(multi_handle, info, &value);
                break;
            }
            
            case 2: {
                // curl_multi_wait
                int timeout_ms = 0;
                int ret = 0;
                unsigned int extra_nfds = 0;
                
                if (Size >= sizeof(int)) {
                    memcpy(&timeout_ms, Data, sizeof(int));
                    Data += sizeof(int);
                    Size -= sizeof(int);
                }
                
                // Parse up to 4 extra fds from fuzzer data
                if (Size >= sizeof(unsigned int)) {
                    memcpy(&extra_nfds, Data, sizeof(unsigned int));
                    extra_nfds = extra_nfds % 5; // Limit to 0-4 fds
                    Data += sizeof(unsigned int);
                    Size -= sizeof(unsigned int);
                }
                
                struct curl_waitfd *extra_fds = NULL;
                if (extra_nfds > 0 && Size >= extra_nfds * sizeof(struct curl_waitfd)) {
                    extra_fds = (struct curl_waitfd *)Data;
                }
                
                curl_multi_wait(multi_handle, extra_fds, extra_nfds, timeout_ms, &ret);
                break;
            }
            
            case 3: {
                // curl_multi_poll
                int timeout_ms = 0;
                int ret = 0;
                unsigned int extra_nfds = 0;
                
                if (Size >= sizeof(int)) {
                    memcpy(&timeout_ms, Data, sizeof(int));
                    Data += sizeof(int);
                    Size -= sizeof(int);
                }
                
                // Parse up to 4 extra fds from fuzzer data
                if (Size >= sizeof(unsigned int)) {
                    memcpy(&extra_nfds, Data, sizeof(unsigned int));
                    extra_nfds = extra_nfds % 5; // Limit to 0-4 fds
                    Data += sizeof(unsigned int);
                    Size -= sizeof(unsigned int);
                }
                
                struct curl_waitfd *extra_fds = NULL;
                if (extra_nfds > 0 && Size >= extra_nfds * sizeof(struct curl_waitfd)) {
                    extra_fds = (struct curl_waitfd *)Data;
                }
                
                curl_multi_poll(multi_handle, extra_fds, extra_nfds, timeout_ms, &ret);
                break;
            }
            
            case 4: {
                // curl_multi_timeout
                long milliseconds = 0;
                curl_multi_timeout(multi_handle, &milliseconds);
                break;
            }
            
            case 5: {
                // curl_multi_perform
                int running_handles = 0;
                curl_multi_perform(multi_handle, &running_handles);
                break;
            }
        }
    }

    curl_multi_cleanup(multi_handle);
    return 0;
}
