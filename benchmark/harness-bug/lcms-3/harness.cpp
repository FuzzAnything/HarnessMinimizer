// Fuzzing harness for Little CMS (lcms) proofing transform APIs
// This harness targets proofing transformation APIs with focus on proofing workflows
// Specifically targets: cmsCreateProofingTransformTHR with 497 undiscovered branches
// Includes virtual profile creation and comprehensive proofing scenarios
// Ensures differentiation from existing harnesses:
// - harness_000 (color transformation)
// - harness_001 (tone curves) 
// - harness_002 (PostScript/DeviceLink)

#include <cstdint>
#include <cstddef>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful proofing transform testing
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Create a context for thread-safe operations
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) return 0;
    
    // Track created profiles for proper cleanup
    std::vector<cmsHPROFILE> profiles;
    std::vector<cmsHTRANSFORM> transforms;
    
    // 1. Create various virtual profiles for proofing scenarios
    
    // Create NULL profile (virtual profile that does nothing)
    cmsHPROFILE nullProfile = cmsCreateNULLProfileTHR(context);
    if (nullProfile != NULL) {
        profiles.push_back(nullProfile);
    }
    
    // Create sRGB profile
    cmsHPROFILE sRGBProfile = cmsCreate_sRGBProfileTHR(context);
    if (sRGBProfile != NULL) {
        profiles.push_back(sRGBProfile);
    }
    
    // Create Lab4 profile
    cmsHPROFILE labProfile = cmsCreateLab4ProfileTHR(context, NULL);
    if (labProfile != NULL) {
        profiles.push_back(labProfile);
    }
    
    // Create XYZ profile  
    cmsHPROFILE xyzProfile = cmsCreateXYZProfileTHR(context);
    if (xyzProfile != NULL) {
        profiles.push_back(xyzProfile);
    }
    
    // Create Gray profile for testing
    cmsHPROFILE grayProfile = cmsCreateGrayProfileTHR(context, NULL, NULL);
    if (grayProfile != NULL) {
        profiles.push_back(grayProfile);
    }
    
    // Need at least 2 profiles for proofing transform
    if (profiles.size() < 2) {
        for (auto profile : profiles) {
            cmsCloseProfile(profile);
        }
        cmsDeleteContext(context);
        return 0;
    }
    
    // 2. Test various proofing transform configurations
    
    // Consume fixed-size parameters from fuzzed input
    cmsUInt32Number inputFormat = fdp.ConsumeIntegralInRange<cmsUInt32Number>(0, 20);
    cmsUInt32Number outputFormat = fdp.ConsumeIntegralInRange<cmsUInt32Number>(0, 20);
    cmsUInt32Number intent = fdp.ConsumeIntegralInRange<cmsUInt32Number>(0, 3);
    cmsUInt32Number proofingIntent = fdp.ConsumeIntegralInRange<cmsUInt32Number>(0, 3);
    cmsUInt32Number flags = fdp.ConsumeIntegral<cmsUInt32Number>();
    
    // Ensure we have valid formats for the profiles being used
    // Use common format types for testing
    cmsUInt32Number formatTypes[] = {
        TYPE_RGB_8, TYPE_RGB_16, TYPE_RGB_FLT,
        TYPE_GRAY_8, TYPE_GRAY_16, TYPE_GRAY_FLT,
        TYPE_Lab_8, TYPE_Lab_16, TYPE_Lab_FLT,
        TYPE_XYZ_16, TYPE_XYZ_FLT, TYPE_XYZ_DBL
    };
    
    const size_t formatTypesCount = sizeof(formatTypes) / sizeof(formatTypes[0]);
    size_t formatIndex = fdp.ConsumeIntegralInRange<size_t>(0, formatTypesCount - 1);
    cmsUInt32Number testInputFormat = formatTypes[formatIndex];
    
    formatIndex = fdp.ConsumeIntegralInRange<size_t>(0, formatTypesCount - 1);
    cmsUInt32Number testOutputFormat = formatTypes[formatIndex];
    // 3. Test proofing transform with softproofing flag
    cmsUInt32Number softproofFlags = flags | cmsFLAGS_SOFTPROOFING;
    
    // Use different profile combinations
    for (size_t i = 0; i < profiles.size() && i + 2 < profiles.size(); i++) {
        cmsHPROFILE inputProfile = profiles[i];
        cmsHPROFILE outputProfile = profiles[(i + 1) % profiles.size()];
        cmsHPROFILE proofingProfile = profiles[(i + 2) % profiles.size()];
        
        // Create proofing transform with softproofing
        cmsHTRANSFORM proofingTransform = cmsCreateProofingTransformTHR(
            context,
            inputProfile,
            testInputFormat,
            outputProfile,
            testOutputFormat,
            proofingProfile,
            intent,
            proofingIntent,
            softproofFlags
        );
        
        if (proofingTransform != NULL) {
            transforms.push_back(proofingTransform);
            
            // Test the transform with random data if we have enough input
            if (fdp.remaining_bytes() > 16) {
                size_t bufferSize = fdp.ConsumeIntegralInRange<size_t>(16, 1024);
                if (bufferSize > fdp.remaining_bytes()) {
                    bufferSize = fdp.remaining_bytes();
                }
                
                if (bufferSize > 0) {
                    std::vector<uint8_t> inputBuffer = fdp.ConsumeBytes<uint8_t>(bufferSize);
                    std::vector<uint8_t> outputBuffer(bufferSize, 0);
                    
                    // Perform the transformation
                    cmsDoTransform(proofingTransform, inputBuffer.data(), outputBuffer.data(), 
                                  static_cast<cmsUInt32Number>(bufferSize));
                    
                    // Test with stride if enough data remains
                    if (fdp.remaining_bytes() >= 4) {
                        cmsUInt32Number stride = fdp.ConsumeIntegralInRange<cmsUInt32Number>(1, 256);
                        cmsDoTransformStride(proofingTransform, inputBuffer.data(), outputBuffer.data(),
                                            static_cast<cmsUInt32Number>(bufferSize), stride);
                    }
                }
            }
        }
    }
    
    // 4. Test proofing transform with gamut check flag
    cmsUInt32Number gamutCheckFlags = flags | cmsFLAGS_GAMUTCHECK;
    
    // Set alarm codes for gamut checking
    cmsUInt16Number alarmCodes[cmsMAXCHANNELS];
    for (int j = 0; j < cmsMAXCHANNELS; j++) {
        alarmCodes[j] = fdp.ConsumeIntegral<cmsUInt16Number>();
    }
    cmsSetAlarmCodesTHR(context, alarmCodes);
    
    // Test with a different profile combination
    if (profiles.size() >= 3) {
        cmsHPROFILE inputProfile = profiles[0];
        cmsHPROFILE outputProfile = profiles[1];
        cmsHPROFILE proofingProfile = profiles[2];
        
        cmsHTRANSFORM gamutTransform = cmsCreateProofingTransformTHR(
            context,
            inputProfile,
            testInputFormat,
            outputProfile,
            testOutputFormat,
            proofingProfile,
            intent,
            proofingIntent,
            gamutCheckFlags
        );
        
        if (gamutTransform != NULL) {
            transforms.push_back(gamutTransform);
            
            // Test gamut checking transform
            if (fdp.remaining_bytes() > 8) {
                size_t testSize = fdp.ConsumeIntegralInRange<size_t>(8, 512);
                if (testSize > 0 && testSize <= fdp.remaining_bytes()) {
                    std::vector<uint8_t> testInput = fdp.ConsumeBytes<uint8_t>(testSize);
                    std::vector<uint8_t> testOutput(testSize, 0);
                    
                    cmsDoTransform(gamutTransform, testInput.data(), testOutput.data(),
                                  static_cast<cmsUInt32Number>(testSize));
                }
            }
        }
    }
    
    // 5. Test proofing transform with combined flags (softproofing + gamut check)
    cmsUInt32Number combinedFlags = flags | cmsFLAGS_SOFTPROOFING | cmsFLAGS_GAMUTCHECK;
    
    if (profiles.size() >= 3) {
        cmsHPROFILE inputProfile = profiles[profiles.size() - 1];
        cmsHPROFILE outputProfile = profiles[0];
        cmsHPROFILE proofingProfile = profiles[1];
        
        cmsHTRANSFORM combinedTransform = cmsCreateProofingTransformTHR(
            context,
            inputProfile,
            testInputFormat,
            outputProfile,
            testOutputFormat,
            proofingProfile,
            intent,
            proofingIntent,
            combinedFlags
        );
        
        if (combinedTransform != NULL) {
            transforms.push_back(combinedTransform);
            
            // Test with black point compensation flag as well
            cmsUInt32Number bpcFlags = combinedFlags | cmsFLAGS_BLACKPOINTCOMPENSATION;
            
            cmsHTRANSFORM bpcTransform = cmsCreateProofingTransformTHR(
                context,
                inputProfile,
                testInputFormat,
                outputProfile,
                testOutputFormat,
                proofingProfile,
                intent,
                proofingIntent,
                bpcFlags
            );
            
            if (bpcTransform != NULL) {
                transforms.push_back(bpcTransform);
                
                // Quick test with minimal data
                if (fdp.remaining_bytes() > 4) {
                    size_t quickSize = fdp.ConsumeIntegralInRange<size_t>(4, 64);
                    if (quickSize > 0 && quickSize <= fdp.remaining_bytes()) {
                        std::vector<uint8_t> quickInput = fdp.ConsumeBytes<uint8_t>(quickSize);
                        std::vector<uint8_t> quickOutput(quickSize, 0);
                        
                        cmsDoTransform(bpcTransform, quickInput.data(), quickOutput.data(),
                                      static_cast<cmsUInt32Number>(quickSize));
                    }
                }
            }
        }
    }
    
    // 6. Test different intents and proofing intents combinations
    
    // Test all intent combinations with a simple profile setup
    if (sRGBProfile != NULL && labProfile != NULL) {
        for (cmsUInt32Number testIntent = 0; testIntent < 4; testIntent++) {
            for (cmsUInt32Number testProofIntent = 0; testProofIntent < 4; testProofIntent++) {
                cmsUInt32Number testFlags = cmsFLAGS_SOFTPROOFING;
                
                cmsHTRANSFORM intentTransform = cmsCreateProofingTransformTHR(
                    context,
                    sRGBProfile,
                    TYPE_RGB_8,
                    labProfile,
                    TYPE_Lab_8,
                    sRGBProfile,  // Use sRGB as proofing profile
                    testIntent,
                    testProofIntent,
                    testFlags
                );
                
                if (intentTransform != NULL) {
                    transforms.push_back(intentTransform);
                }
            }
        }
    }
    
    // 7. Test with different format combinations
    
    if (sRGBProfile != NULL && nullProfile != NULL) {
        // Test various format combinations
        cmsUInt32Number formatCombos[][2] = {
            {TYPE_RGB_8, TYPE_GRAY_8},
            {TYPE_RGB_16, TYPE_GRAY_16},
            {TYPE_RGB_FLT, TYPE_GRAY_FLT},
            {TYPE_RGB_8, TYPE_RGB_16},
            {TYPE_RGB_16, TYPE_RGB_FLT}
        };
        
        for (size_t combo = 0; combo < sizeof(formatCombos)/sizeof(formatCombos[0]); combo++) {
            cmsHTRANSFORM formatTransform = cmsCreateProofingTransformTHR(
                context,
                sRGBProfile,
                formatCombos[combo][0],
                nullProfile,
                formatCombos[combo][1],
                sRGBProfile,
                INTENT_RELATIVE_COLORIMETRIC,
                INTENT_RELATIVE_COLORIMETRIC,
                cmsFLAGS_SOFTPROOFING
            );
            
            if (formatTransform != NULL) {
                transforms.push_back(formatTransform);
            }
        }
    }
    
    // 8. Test non-THR version as well (for completeness)
    if (sRGBProfile != NULL && labProfile != NULL) {
        cmsHTRANSFORM nonThrTransform = cmsCreateProofingTransform(
            sRGBProfile,
            TYPE_RGB_8,
            labProfile,
            TYPE_Lab_8,
            sRGBProfile,
            intent,
            proofingIntent,
            cmsFLAGS_SOFTPROOFING
        );
        
        if (nonThrTransform != NULL) {
            transforms.push_back(nonThrTransform);
        }
    }
    
    // 9. Cleanup all transforms
    for (auto transform : transforms) {
        cmsDeleteTransform(transform);
    }
    
    // 10. Cleanup all profiles
    for (auto profile : profiles) {
        cmsCloseProfile(profile);
    }
    
    // 11. Delete context
    cmsDeleteContext(context);
    
    return 0;
}
