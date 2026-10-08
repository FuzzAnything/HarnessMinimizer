#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <cstdio>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check for meaningful fuzzing
    if (size < 128) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // ========== PART 1: File-based profile operations ==========
    
    // Create temporary file with fuzzer data as ICC profile content
    const char* temp_profile_file = "/tmp/fuzz_profile.icc";
    
    // Consume part of input for the profile data
    size_t profile_data_size = fdp.ConsumeIntegralInRange<size_t>(128, 4096);
    if (profile_data_size > fdp.remaining_bytes()) {
        profile_data_size = fdp.remaining_bytes();
    }
    
    std::vector<uint8_t> profile_data = fdp.ConsumeBytes<uint8_t>(profile_data_size);
    
    // Write profile data to temporary file
    std::ofstream profile_file(temp_profile_file, std::ios::binary);
    if (profile_file.is_open()) {
        profile_file.write(reinterpret_cast<const char*>(profile_data.data()), profile_data.size());
        profile_file.close();
        
        // Test 1: cmsOpenProfileFromFile with different access modes
        const char* access_modes[] = {"r", "w", "rb", "wb"};
        int mode_index = fdp.ConsumeIntegralInRange<int>(0, 3);
        
        cmsHPROFILE hProfileFile = cmsOpenProfileFromFile(temp_profile_file, access_modes[mode_index]);
        if (hProfileFile != NULL) {
            // Perform some operations on the opened profile
            cmsColorSpaceSignature color_space = cmsGetColorSpace(hProfileFile);
            cmsColorSpaceSignature pcs = cmsGetPCS(hProfileFile);
            cmsUInt32Number intent = cmsGetHeaderRenderingIntent(hProfileFile);
            
            // Read tag count if profile is readable
            if (mode_index == 0 || mode_index == 2) {  // "r" or "rb" modes
                cmsInt32Number tag_count = cmsGetTagCount(hProfileFile);
                if (tag_count > 0 && tag_count < 100) {
                    // Read first few tags
                    for (cmsInt32Number i = 0; i < tag_count && i < 5; i++) {
                        cmsTagSignature sig = cmsGetTagSignature(hProfileFile, i);
                        cmsReadTag(hProfileFile, sig);
                    }
                }
            }
            
            // Test 2: cmsOpenProfileFromFileTHR with context
            cmsContext context = cmsCreateContext(NULL, NULL);
            if (context != NULL) {
                cmsHPROFILE hProfileFileTHR = cmsOpenProfileFromFileTHR(context, temp_profile_file, access_modes[mode_index]);
                if (hProfileFileTHR != NULL) {
                    cmsCloseProfile(hProfileFileTHR);
                }
                cmsDeleteContext(context);
            }
            
            // Test 3: cmsSaveProfileToFile if we have enough remaining data
            if (fdp.remaining_bytes() > 0) {
                const char* temp_save_file = "/tmp/fuzz_save_profile.icc";
                
                // Try to save the profile to another file
                cmsBool save_result = cmsSaveProfileToFile(hProfileFile, temp_save_file);
                // Note: save_result may be FALSE for invalid profiles, that's OK
                
                // Clean up saved file if it exists
                remove(temp_save_file);
            }
            
            cmsCloseProfile(hProfileFile);
        }
        
        // ========== PART 2: Stream-based profile operations ==========
        
        // Re-open the file as a FILE* stream
        FILE* file_stream = fopen(temp_profile_file, "rb");
        if (file_stream != NULL) {
            // Test 4: cmsOpenProfileFromStream
            cmsHPROFILE hProfileStream = cmsOpenProfileFromStream(file_stream, "r");
            if (hProfileStream != NULL) {
                // Perform some operations
                cmsInt32Number tag_count = cmsGetTagCount(hProfileStream);
                cmsGetProfileInfo(hProfileStream, cmsInfoDescription, "en", "US", NULL, 0);
                
                // Test 5: cmsOpenProfileFromStreamTHR with context
                cmsContext stream_context = cmsCreateContext(NULL, NULL);
                if (stream_context != NULL) {
                    // Need to rewind or reopen stream for second open
                    rewind(file_stream);
                    cmsHPROFILE hProfileStreamTHR = cmsOpenProfileFromStreamTHR(stream_context, file_stream, "r");
                    if (hProfileStreamTHR != NULL) {
                        cmsCloseProfile(hProfileStreamTHR);
                    }
                    cmsDeleteContext(stream_context);
                }
                
                // Test 6: cmsSaveProfileToStream if we have remaining data
                if (fdp.remaining_bytes() > 0) {
                    const char* temp_stream_save = "/tmp/fuzz_stream_save.icc";
                    FILE* save_stream = fopen(temp_stream_save, "wb");
                    if (save_stream != NULL) {
                        cmsBool stream_save_result = cmsSaveProfileToStream(hProfileStream, save_stream);
                        fclose(save_stream);
                        remove(temp_stream_save);
                    }
                }
                
                cmsCloseProfile(hProfileStream);
            }
            
            fclose(file_stream);
        }
        
        // ========== PART 3: IO handler operations ==========
        
        // Test IO handler creation and profile opening from IO handler
        if (fdp.remaining_bytes() > 0) {
            cmsContext io_context = cmsCreateContext(NULL, NULL);
            if (io_context != NULL) {
                // Create IO handler from file
                cmsIOHANDLER* io_handler = cmsOpenIOhandlerFromFile(io_context, temp_profile_file, "r");
                if (io_handler != NULL) {
                    // Test cmsOpenProfileFromIOhandlerTHR
                    cmsHPROFILE hProfileIO = cmsOpenProfileFromIOhandlerTHR(io_context, io_handler);
                    if (hProfileIO != NULL) {
                        // Test cmsGetProfileIOhandler
                        cmsIOHANDLER* retrieved_io = cmsGetProfileIOhandler(hProfileIO);
                        if (retrieved_io != NULL) {
                            // IO handler retrieved successfully
                        }
                        
                        cmsCloseProfile(hProfileIO);
                    } else {
                        // If opening from IO handler failed, we still need to close it
                        cmsCloseIOhandler(io_handler);
                    }
                }
                
                cmsDeleteContext(io_context);
            }
        }
        
        // ========== PART 4: Memory-based operations for comparison ==========
        
        // Test cmsOpenProfileFromMem for comparison (this should work if data is valid)
        if (profile_data.size() > 0) {
            cmsHPROFILE hProfileMem = cmsOpenProfileFromMem(profile_data.data(), static_cast<cmsUInt32Number>(profile_data.size()));
            if (hProfileMem != NULL) {
                // Also test cmsSaveProfileToMem
                if (fdp.remaining_bytes() > sizeof(cmsUInt32Number)) {
                    cmsUInt32Number bytes_needed = 0;
                    cmsSaveProfileToMem(hProfileMem, NULL, &bytes_needed);
                    
                    if (bytes_needed > 0 && bytes_needed < 1024 * 1024) {  // Reasonable size
                        std::vector<uint8_t> saved_buffer(bytes_needed);
                        cmsSaveProfileToMem(hProfileMem, saved_buffer.data(), &bytes_needed);
                    }
                }
                
                cmsCloseProfile(hProfileMem);
            }
        }
        
        // Clean up temporary file
        remove(temp_profile_file);
    }
    
    // ========== PART 5: Additional file/stream edge cases ==========
    
    // Test with empty/invalid file names
    if (fdp.remaining_bytes() > 0) {
        // Consume a string that might be an invalid filename
        std::string invalid_filename = fdp.ConsumeRandomLengthString(64);
        cmsHPROFILE hInvalid = cmsOpenProfileFromFile(invalid_filename.c_str(), "r");
        // Should be NULL for invalid file, that's expected
        
        // Test with different access mode combinations
        const char* test_modes[] = {"r", "w", "rb", "wb", "r+", "w+"};
        for (int i = 0; i < 6 && fdp.remaining_bytes() > 0; i++) {
            // Create a small test file
            const char* test_file = "/tmp/test_mode.icc";
            std::ofstream test_out(test_file, std::ios::binary);
            if (test_out.is_open()) {
                test_out.write("test", 4);
                test_out.close();
                
                cmsHPROFILE hTest = cmsOpenProfileFromFile(test_file, test_modes[i]);
                if (hTest != NULL) {
                    cmsCloseProfile(hTest);
                }
                
                remove(test_file);
            }
        }
    }
    
    return 0;
}
