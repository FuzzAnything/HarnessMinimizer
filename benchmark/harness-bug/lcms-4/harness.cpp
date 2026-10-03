// Fuzzing harness for LittleCMS2 library
// Targets virtual profile creation APIs and gamut detection functions
// harness_002.cpp - Focus on cmsvirt.c and cmsgmt.c modules

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"
#include "lcms2_plugin.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

// Helper function to generate random CIExyY point from fuzzer data
static void GenerateCIExyY(FuzzedDataProvider& fdp, cmsCIExyY* point) {
    point->x = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    point->y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    point->Y = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
}

// Helper function to generate random CIExyYTRIPLE from fuzzer data
static void GenerateCIExyYTRIPLE(FuzzedDataProvider& fdp, cmsCIExyYTRIPLE* primaries) {
    GenerateCIExyY(fdp, &primaries->Red);
    GenerateCIExyY(fdp, &primaries->Green);
    GenerateCIExyY(fdp, &primaries->Blue);
}

// Helper function to create a simple tone curve from fuzzer data
static cmsToneCurve* CreateToneCurveFromFDP(FuzzedDataProvider& fdp) {
    cmsUInt32Number nPoints = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 20);
    std::vector<cmsFloat32Number> values(nPoints);
    
    for (cmsUInt32Number i = 0; i < nPoints; i++) {
        values[i] = fdp.ConsumeFloatingPointInRange<cmsFloat32Number>(0.0f, 1.0f);
    }
    
    return cmsBuildTabulatedToneCurveFloat(0, nPoints, values.data());
}

// Test virtual profile creation APIs
static void TestVirtualProfileCreation(FuzzedDataProvider& fdp) {
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve* transferFunctions[3] = {NULL, NULL, NULL};
    
    // Generate random parameters for profile creation
    GenerateCIExyY(fdp, &whitePoint);
    GenerateCIExyYTRIPLE(fdp, &primaries);
    
    // Create tone curves for RGB channels
    for (int i = 0; i < 3; i++) {
        if (fdp.ConsumeBool()) {
            transferFunctions[i] = CreateToneCurveFromFDP(fdp);
        }
    }
    
    // Test various virtual profile creation APIs
    cmsHPROFILE profiles[10];
    int profileCount = 0;
    
    // 1. Create RGB profile
    profiles[profileCount++] = cmsCreateRGBProfile(&whitePoint, &primaries, transferFunctions);
    
    // 2. Create Gray profile (single tone curve)
    cmsToneCurve* grayCurve = CreateToneCurveFromFDP(fdp);
    profiles[profileCount++] = cmsCreateGrayProfile(&whitePoint, grayCurve);
    
    // 3. Create Lab4 profile
    profiles[profileCount++] = cmsCreateLab4Profile(NULL);
    
    // 4. Create XYZ profile
    profiles[profileCount++] = cmsCreateXYZProfile();
    
    // 5. Create sRGB profile
    profiles[profileCount++] = cmsCreate_sRGBProfile();
    
    // 6. Create NULL profile
    profiles[profileCount++] = cmsCreateNULLProfile();
    
    // 7. Create Lab2 profile
    profiles[profileCount++] = cmsCreateLab2Profile(&whitePoint);
    
    // Clean up created profiles
    for (int i = 0; i < profileCount; i++) {
        if (profiles[i]) {
            cmsCloseProfile(profiles[i]);
        }
    }
    
    // Clean up tone curves
    for (int i = 0; i < 3; i++) {
        if (transferFunctions[i]) {
            cmsFreeToneCurve(transferFunctions[i]);
        }
    }
    if (grayCurve) {
        cmsFreeToneCurve(grayCurve);
    }
}

// Test gamut detection and checking functions
static void TestGamutDetection(FuzzedDataProvider& fdp) {
    // Create some profiles for testing
    cmsHPROFILE hSRGB = cmsCreate_sRGBProfile();
    cmsHPROFILE hLab = cmsCreateLab4Profile(NULL);
    cmsHPROFILE hGray = cmsCreateGrayProfile(NULL, NULL);
    
    if (!hSRGB || !hLab || !hGray) {
        if (hSRGB) cmsCloseProfile(hSRGB);
        if (hLab) cmsCloseProfile(hLab);
        if (hGray) cmsCloseProfile(hGray);
        return;
    }
    
    // Create profile array for extended transform
    cmsHPROFILE hProfiles[3];
    cmsBool BPC[3];
    cmsUInt32Number Intents[3];
    cmsFloat64Number AdaptationStates[3];
    
    hProfiles[0] = hSRGB;
    hProfiles[1] = hLab;
    hProfiles[2] = hGray;
    
    for (int i = 0; i < 3; i++) {
        BPC[i] = fdp.ConsumeBool();
        Intents[i] = fdp.ConsumeIntegralInRange<cmsUInt32Number>(0, 3);
        AdaptationStates[i] = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 1.0);
    }
    
    // Test cmsCreateExtendedTransform with gamut checking
    cmsUInt32Number nGamutPCSposition = fdp.ConsumeIntegralInRange<cmsUInt32Number>(1, 2);
    cmsUInt32Number dwFlags = cmsFLAGS_GAMUTCHECK;
    
    if (fdp.ConsumeBool()) {
        dwFlags |= cmsFLAGS_BLACKPOINTCOMPENSATION;
    }
    if (fdp.ConsumeBool()) {
        dwFlags |= cmsFLAGS_HIGHRESPRECALC;
    }
    
    cmsHTRANSFORM hTransform = cmsCreateExtendedTransform(
        0, 3, hProfiles, BPC, Intents, AdaptationStates,
        hSRGB, nGamutPCSposition,
        TYPE_RGB_8, TYPE_Lab_8, dwFlags);
    
    if (hTransform) {
        // Test the transform with some random colors
        for (int i = 0; i < 5 && fdp.remaining_bytes() > 3; i++) {
            cmsUInt8Number input[3], output[3];
            input[0] = fdp.ConsumeIntegral<uint8_t>();
            input[1] = fdp.ConsumeIntegral<uint8_t>();
            input[2] = fdp.ConsumeIntegral<uint8_t>();
            
            cmsDoTransform(hTransform, input, output, 1);
        }
        
        cmsDeleteTransform(hTransform);
    }
    
    // Test proofing transform with gamut checking
    cmsHTRANSFORM hProofing = cmsCreateProofingTransform(
        hSRGB, TYPE_RGB_8,
        hSRGB, TYPE_RGB_8,
        hLab, INTENT_RELATIVE_COLORIMETRIC, INTENT_RELATIVE_COLORIMETRIC,
        cmsFLAGS_GAMUTCHECK);
    
    if (hProofing) {
        // Test with some random colors
        for (int i = 0; i < 5 && fdp.remaining_bytes() > 3; i++) {
            cmsUInt8Number input[3], output[3];
            input[0] = fdp.ConsumeIntegral<uint8_t>();
            input[1] = fdp.ConsumeIntegral<uint8_t>();
            input[2] = fdp.ConsumeIntegral<uint8_t>();
            
            cmsDoTransform(hProofing, input, output, 1);
        }
        
        cmsDeleteTransform(hProofing);
    }
    
    // Test gamut boundary description APIs
    cmsHANDLE hGBD = cmsGBDAlloc(0);
    if (hGBD) {
        // Add some random Lab points
        for (int i = 0; i < 10 && fdp.remaining_bytes() > 24; i++) {
            cmsCIELab lab;
            lab.L = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 100.0);
            lab.a = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-128.0, 128.0);
            lab.b = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-128.0, 128.0);
            
            cmsGDBAddPoint(hGBD, &lab);
        }
        
        // Compute gamut boundary
        cmsGDBCompute(hGBD, 0);
        
        // Check some random points
        for (int i = 0; i < 5 && fdp.remaining_bytes() > 24; i++) {
            cmsCIELab lab;
            lab.L = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 100.0);
            lab.a = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-128.0, 128.0);
            lab.b = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-128.0, 128.0);
            
            cmsGDBCheckPoint(hGBD, &lab);
        }
        
        cmsGBDFree(hGBD);
    }
    
    // Test alarm codes for gamut checking
    cmsUInt16Number alarmCodes[cmsMAXCHANNELS];
    for (int i = 0; i < cmsMAXCHANNELS; i++) {
        alarmCodes[i] = fdp.ConsumeIntegral<uint16_t>();
    }
    cmsSetAlarmCodes(alarmCodes);
    
    cmsUInt16Number retrievedCodes[cmsMAXCHANNELS];
    cmsGetAlarmCodes(retrievedCodes);
    
    // Test desaturation (poor man's gamut mapping)
    cmsCIELab lab;
    lab.L = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 100.0);
    lab.a = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-128.0, 128.0);
    lab.b = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-128.0, 128.0);
    
    cmsDesaturateLab(&lab, 50.0, -50.0, 50.0, -50.0);
    
    // Clean up
    cmsCloseProfile(hSRGB);
    cmsCloseProfile(hLab);
    cmsCloseProfile(hGray);
}

// Test ink limiting device link profile creation
static void TestInkLimiting(FuzzedDataProvider& fdp) {
    cmsFloat64Number limit = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 400.0);
    
    // Test CMYK ink limiting
    cmsHPROFILE hCMYK = cmsCreateInkLimitingDeviceLink(cmsSigCmykData, limit);
    if (hCMYK) {
        cmsCloseProfile(hCMYK);
    }
    
    // Test with different color spaces
    cmsColorSpaceSignature spaces[] = {
        cmsSigRgbData, cmsSigCmykData, cmsSigCmyData, cmsSigMCH6Data
    };
    
    for (cmsColorSpaceSignature space : spaces) {
        if (fdp.remaining_bytes() > sizeof(cmsFloat64Number)) {
            limit = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.0, 400.0);
            cmsHPROFILE hLink = cmsCreateInkLimitingDeviceLink(space, limit);
            if (hLink) {
                cmsCloseProfile(hLink);
            }
        }
    }
}

// Test linearization device link profile creation
static void TestLinearizationDeviceLink(FuzzedDataProvider& fdp) {
    cmsToneCurve* curves[4] = {NULL, NULL, NULL, NULL};
    
    // Create some tone curves
    for (int i = 0; i < 4 && fdp.remaining_bytes() > 10; i++) {
        if (fdp.ConsumeBool()) {
            curves[i] = CreateToneCurveFromFDP(fdp);
        }
    }
    
    // Test with different color spaces
    cmsColorSpaceSignature spaces[] = {
        cmsSigRgbData, cmsSigCmykData, cmsSigGrayData, cmsSigMCH6Data
    };
    
    for (cmsColorSpaceSignature space : spaces) {
        cmsHPROFILE hLink = cmsCreateLinearizationDeviceLink(space, curves);
        if (hLink) {
            cmsCloseProfile(hLink);
        }
    }
    
    // Clean up tone curves
    for (int i = 0; i < 4; i++) {
        if (curves[i]) {
            cmsFreeToneCurve(curves[i]);
        }
    }
}

// Main fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 128) {
        return 0;  // Need minimum data for meaningful testing
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Test different virtual profile creation and gamut detection scenarios
    // based on fuzzer input to maximize coverage diversity
    
    uint8_t testScenario = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    switch (testScenario) {
        case 0:
            TestVirtualProfileCreation(fdp);
            break;
        case 1:
            TestGamutDetection(fdp);
            break;
        case 2:
            TestInkLimiting(fdp);
            break;
        case 3:
            TestLinearizationDeviceLink(fdp);
            break;
    }
    
    return 0;
}
