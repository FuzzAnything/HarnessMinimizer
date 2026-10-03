// Little-CMS fuzzing harness for virtual profile creation and comprehensive file I/O operations
// Targets uncovered high-complexity APIs in cmsvirt.c and cmsio0.c:
// - cmsCreateLinearizationDeviceLink, cmsCreateNULLProfile, cmsCreate_OkLabProfile
// - cmsOpenProfileFromFile, cmsOpenProfileFromStream, cmsSaveProfileToFile
// - cmsReadRawTag, cmsGetProfileInfo family
// This harness is semantically unique from existing harnesses:
// - harness_000: Basic color transformations between profiles  
// - harness_001: PostScript color resource generation
// - harness_002: Advanced proofing transforms and device link operations
// - harness_003: CGATS/IT8 file parsing and Cube file device link creation
// - harness_004: Comprehensive proofing workflows and special profile types
// - harness_005: Profile I/O lifecycle operations (memory-based)
// - harness_006: Virtual profile creation + file/stream I/O operations

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <cstring>

#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size needed for comprehensive testing
    // Need enough for: operation selection, tone curve data, filenames, etc.
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size parameters first
    uint8_t test_scenario = fdp.ConsumeIntegral<uint8_t>() % 4;  // 0-3 for different test scenarios
    uint8_t use_thread_safe = fdp.ConsumeBool();  // Use THR versions of APIs
    uint8_t color_space = fdp.ConsumeIntegral<uint8_t>() % 4;  // 0=RGB, 1=CMYK, 2=Gray, 3=Lab
    uint8_t num_tone_points = fdp.ConsumeIntegralInRange<uint8_t>(2, 10);  // For tone curves
    uint8_t profile_type = fdp.ConsumeIntegral<uint8_t>() % 3;  // 0=Linearization, 1=NULL, 2=OkLab
    
    // Consume floating point parameters
    double gamma_value = fdp.ConsumeFloatingPointInRange<double>(0.5, 5.0);
    double white_point_x = fdp.ConsumeFloatingPointInRange<double>(0.1, 0.9);
    double white_point_y = fdp.ConsumeFloatingPointInRange<double>(0.1, 0.9);
    
    // Consume strings for filenames
    std::string temp_filename1 = "/tmp/lcms_fuzz_" + fdp.ConsumeRandomLengthString(16);
    std::string temp_filename2 = "/tmp/lcms_fuzz_" + fdp.ConsumeRandomLengthString(16);
    
    // Create a context if using thread-safe APIs
    cmsContext context = NULL;
    if (use_thread_safe) {
        context = cmsCreateContext(NULL, NULL);
        if (context == NULL) {
            // Fall back to non-thread-safe testing
            use_thread_safe = 0;
        }
    }
    
    // PHASE 1: CREATE VIRTUAL PROFILES USING UNCOVERED APIS
    
    cmsHPROFILE virtual_profiles[3] = {NULL, NULL, NULL};
    int profile_count = 0;
    
    // 1. Create Linearization Device Link Profile
    if (profile_type == 0 || test_scenario == 0) {
        // Create tone curves for the device link
        cmsToneCurve* tone_curves[3] = {NULL, NULL, NULL};
        
        // Build gamma curves for RGB channels
        for (int i = 0; i < 3; i++) {
            tone_curves[i] = cmsBuildGamma(NULL, gamma_value + (i * 0.1));
            if (tone_curves[i] == NULL) {
                // Clean up any already created curves
                for (int j = 0; j < i; j++) {
                    cmsFreeToneCurve(tone_curves[j]);
                }
                break;
            }
        }
        
        if (tone_curves[0] && tone_curves[1] && tone_curves[2]) {
            cmsColorSpaceSignature spaceSig;
            switch (color_space) {
                case 0: spaceSig = cmsSigRgbData; break;
                case 1: spaceSig = cmsSigCmykData; break;
                case 2: spaceSig = cmsSigGrayData; break;
                case 3: spaceSig = cmsSigLabData; break;
                default: spaceSig = cmsSigRgbData;
            }
            
            if (use_thread_safe && context) {
                virtual_profiles[profile_count] = cmsCreateLinearizationDeviceLinkTHR(
                    context, spaceSig, tone_curves);
            } else {
                virtual_profiles[profile_count] = cmsCreateLinearizationDeviceLink(
                    spaceSig, tone_curves);
            }
            
            if (virtual_profiles[profile_count]) {
                profile_count++;
            }
            
            // Free tone curves
            for (int i = 0; i < 3; i++) {
                cmsFreeToneCurve(tone_curves[i]);
            }
        }
    }
    
    // 2. Create NULL Profile
    if (profile_type == 1 || test_scenario == 1) {
        if (use_thread_safe && context) {
            virtual_profiles[profile_count] = cmsCreateNULLProfileTHR(context);
        } else {
            virtual_profiles[profile_count] = cmsCreateNULLProfile();
        }
        
        if (virtual_profiles[profile_count]) {
            profile_count++;
        }
    }
    
    // 3. Create OkLab Profile
    if (profile_type == 2 || test_scenario == 2) {
        // cmsCreate_OkLabProfile requires a context parameter
        virtual_profiles[profile_count] = cmsCreate_OkLabProfile(context);
        
        if (virtual_profiles[profile_count]) {
            profile_count++;
        }
    }
    
    // If no profiles were created, create a simple sRGB profile as fallback
    if (profile_count == 0) {
        if (use_thread_safe && context) {
            virtual_profiles[0] = cmsCreate_sRGBProfileTHR(context);
        } else {
            virtual_profiles[0] = cmsCreate_sRGBProfile();
        }
        if (virtual_profiles[0]) {
            profile_count = 1;
        } else {
            if (context) cmsDeleteContext(context);
            return 0;
        }
    }
    
    // PHASE 2: FILE I/O OPERATIONS WITH CREATED PROFILES
    
    for (int i = 0; i < profile_count; i++) {
        cmsHPROFILE profile = virtual_profiles[i];
        if (!profile) continue;
        
        // Save profile to file
        if (fdp.ConsumeBool()) {
            const char* filename = temp_filename1.c_str();
            cmsBool save_result = cmsSaveProfileToFile(profile, filename);
            (void)save_result; // Use result to avoid unused variable warning
            
            // Open profile from file (testing target API)
            cmsHPROFILE reopened_profile = NULL;
            if (use_thread_safe && context) {
                reopened_profile = cmsOpenProfileFromFileTHR(context, filename, "r");
            } else {
                reopened_profile = cmsOpenProfileFromFile(filename, "r");
            }
            
            if (reopened_profile) {
                // Test profile information APIs
                wchar_t wbuffer[256];
                char buffer[256];
                char utf8_buffer[256];
                
                cmsGetProfileInfo(reopened_profile, cmsInfoDescription, "en", "US", wbuffer, sizeof(wbuffer)/sizeof(wchar_t));
                cmsGetProfileInfoASCII(reopened_profile, cmsInfoDescription, "en", "US", buffer, sizeof(buffer));
                cmsGetProfileInfoUTF8(reopened_profile, cmsInfoDescription, "en", "US", utf8_buffer, sizeof(utf8_buffer));
                
                // Test cmsGetProfileInfo with different info types
                cmsGetProfileInfo(reopened_profile, cmsInfoManufacturer, "en", "US", NULL, 0);
                cmsGetProfileInfoASCII(reopened_profile, cmsInfoManufacturer, "en", "US", NULL, 0);
                cmsGetProfileInfoUTF8(reopened_profile, cmsInfoManufacturer, "en", "US", NULL, 0);
                
                cmsGetProfileInfo(reopened_profile, cmsInfoModel, "en", "US", NULL, 0);
                cmsGetProfileInfoASCII(reopened_profile, cmsInfoModel, "en", "US", NULL, 0);
                cmsGetProfileInfoUTF8(reopened_profile, cmsInfoModel, "en", "US", NULL, 0);
                
                cmsGetProfileInfo(reopened_profile, cmsInfoCopyright, "en", "US", NULL, 0);
                cmsGetProfileInfoASCII(reopened_profile, cmsInfoCopyright, "en", "US", NULL, 0);
                cmsGetProfileInfoUTF8(reopened_profile, cmsInfoCopyright, "en", "US", NULL, 0);
                
                // Close the reopened profile
                cmsCloseProfile(reopened_profile);
            }
            
            // Clean up temp file
            unlink(filename);
        }
        
        // Test stream operations if there's enough data
        if (fdp.ConsumeBool() && fdp.remaining_bytes() > 100) {
            // Create a temporary file for stream testing
            FILE* stream = fopen(temp_filename2.c_str(), "wb");
            if (stream) {
                // Save profile to stream
                cmsBool stream_save_result = cmsSaveProfileToStream(profile, stream);
                fclose(stream);
                
                if (stream_save_result) {
                    // Open profile from stream
                    stream = fopen(temp_filename2.c_str(), "rb");
                    if (stream) {
                        cmsHPROFILE stream_profile = NULL;
                        if (use_thread_safe && context) {
                            stream_profile = cmsOpenProfileFromStreamTHR(context, stream, "r");
                        } else {
                            stream_profile = cmsOpenProfileFromStream(stream, "r");
                        }
                        
                        if (stream_profile) {
                            // Test cmsReadRawTag on the stream-opened profile
                            // Try reading some common tag signatures
                            cmsTagSignature tag_sigs[] = {
                                cmsSigRedColorantTag,
                                cmsSigGreenColorantTag,
                                cmsSigBlueColorantTag,
                                cmsSigCopyrightTag,
                                cmsSigProfileDescriptionTag
                            };
                            
                            for (int tag_idx = 0; tag_idx < 5; tag_idx++) {
                                // First get size
                                cmsUInt32Number tag_size = cmsReadRawTag(
                                    stream_profile, tag_sigs[tag_idx], NULL, 0);
                                
                                if (tag_size > 0 && tag_size < 1024 * 1024) {
                                    std::vector<uint8_t> tag_buffer(tag_size);
                                    cmsUInt32Number read_size = cmsReadRawTag(
                                        stream_profile, tag_sigs[tag_idx], 
                                        tag_buffer.data(), tag_size);
                                    (void)read_size; // Use to avoid warning
                                }
                            }
                            
                            cmsCloseProfile(stream_profile);
                        }
                        fclose(stream);
                    }
                }
                
                // Clean up temp file
                unlink(temp_filename2.c_str());
            }
        }
    }
    
    // PHASE 3: ADDITIONAL TAG READING TESTS ON ORIGINAL PROFILES
    
    for (int i = 0; i < profile_count; i++) {
        if (!virtual_profiles[i]) continue;
        
        // Test cmsReadRawTag on original virtual profiles
        cmsTagSignature test_tags[] = {
            cmsSigProfileDescriptionTag,
            cmsSigCopyrightTag,
            cmsSigMediaWhitePointTag,
            cmsSigRedTRCTag,
            cmsSigGreenTRCTag,
            cmsSigBlueTRCTag
        };
        
        for (int tag_idx = 0; tag_idx < 6; tag_idx++) {
            // Get tag size first
            cmsUInt32Number tag_size = cmsReadRawTag(
                virtual_profiles[i], test_tags[tag_idx], NULL, 0);
            
            if (tag_size > 0 && tag_size < 1024 * 1024) {
                std::vector<uint8_t> tag_buffer(tag_size);
                cmsUInt32Number bytes_read = cmsReadRawTag(
                    virtual_profiles[i], test_tags[tag_idx],
                    tag_buffer.data(), tag_size);
                (void)bytes_read; // Use to avoid warning
            }
        }
        
        // Test more cmsGetProfileInfo variants
        const char* languages[] = {"en", "fr", "de", "es", NULL};
        const char* countries[] = {"US", "GB", "FR", "DE", NULL};
        
        wchar_t wbuffer[256];
        char buffer[256];
        char utf8_buffer[256];
        
        for (int lang_idx = 0; lang_idx < 4 && languages[lang_idx]; lang_idx++) {
            for (int country_idx = 0; country_idx < 4 && countries[country_idx]; country_idx++) {
                // Test with wchar_t version
                cmsGetProfileInfo(virtual_profiles[i], cmsInfoDescription,
                    languages[lang_idx], countries[country_idx],
                    wbuffer, sizeof(wbuffer)/sizeof(wchar_t));
                
                // Test with ASCII version
                cmsGetProfileInfoASCII(virtual_profiles[i], cmsInfoDescription,
                    languages[lang_idx], countries[country_idx],
                    buffer, sizeof(buffer));
                
                // Test with UTF8 version
                cmsGetProfileInfoUTF8(virtual_profiles[i], cmsInfoDescription,
                    languages[lang_idx], countries[country_idx],
                    utf8_buffer, sizeof(utf8_buffer));
            }
        }
    }
    
    // PHASE 4: CLEANUP
    
    // Close all created profiles
    for (int i = 0; i < profile_count; i++) {
        if (virtual_profiles[i]) {
            cmsCloseProfile(virtual_profiles[i]);
        }
    }
    
    // Delete context if created
    if (context) {
        cmsDeleteContext(context);
    }
    
    return 0;
}
