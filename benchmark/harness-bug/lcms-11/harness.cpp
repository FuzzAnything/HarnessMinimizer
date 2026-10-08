// Fuzzing harness for Little CMS (lcms) Tone Curve API subsystem
// This harness targets tone curve creation, manipulation, evaluation, and analysis APIs
// Avoids problematic profile parsing APIs that caused crashes in harness_000
// Implements comprehensive coverage of 20+ tone curve related APIs

#include <cstdint>
#include <cstddef>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need minimum input for meaningful testing of tone curves
    // We need space for various parameters and curve data
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Create a context for tone curve operations
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) return 0;
    
    // Track created curves for cleanup
    std::vector<cmsToneCurve*> curves;
    
    // 1. Build various types of tone curves
    
    // Build parametric tone curve
    cmsInt32Number parametricType = fdp.ConsumeIntegralInRange<cmsInt32Number>(-10, 30);
    cmsFloat64Number params[10];
    for (int i = 0; i < 10 && fdp.remaining_bytes() > 0; i++) {
        params[i] = fdp.ConsumeFloatingPoint<double>();
    }
    
    cmsToneCurve* parametricCurve = cmsBuildParametricToneCurve(context, parametricType, params);
    if (parametricCurve != NULL) {
        curves.push_back(parametricCurve);
    }
    
    // Build gamma curve
    cmsFloat64Number gamma = fdp.ConsumeFloatingPoint<double>();
    cmsToneCurve* gammaCurve = cmsBuildGamma(context, gamma);
    if (gammaCurve != NULL) {
        curves.push_back(gammaCurve);
    }
    
    // Build tabulated tone curve (16-bit)
    cmsUInt32Number nEntries16 = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 256);
    if (nEntries16 * sizeof(cmsUInt16Number) <= fdp.remaining_bytes()) {
        std::vector<cmsUInt16Number> values16(nEntries16);
        for (cmsUInt32Number i = 0; i < nEntries16 && fdp.remaining_bytes() > 0; i++) {
            values16[i] = fdp.ConsumeIntegral<cmsUInt16Number>();
        }
        cmsToneCurve* tabulated16Curve = cmsBuildTabulatedToneCurve16(context, nEntries16, values16.data());
        if (tabulated16Curve != NULL) {
            curves.push_back(tabulated16Curve);
        }
    }
    
    // Build tabulated tone curve (float)
    cmsUInt32Number nEntriesFloat = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 256);
    if (nEntriesFloat * sizeof(cmsFloat32Number) <= fdp.remaining_bytes()) {
        std::vector<cmsFloat32Number> valuesFloat(nEntriesFloat);
        for (cmsUInt32Number i = 0; i < nEntriesFloat && fdp.remaining_bytes() > 0; i++) {
            valuesFloat[i] = fdp.ConsumeFloatingPoint<float>();
        }
        cmsToneCurve* tabulatedFloatCurve = cmsBuildTabulatedToneCurveFloat(context, nEntriesFloat, valuesFloat.data());
        if (tabulatedFloatCurve != NULL) {
            curves.push_back(tabulatedFloatCurve);
        }
    }
    
    // Build segmented tone curve - careful with Type 0 segments (sampled segments)
    cmsUInt32Number nSegments = fdp.ConsumeIntegralInRange<cmsUInt32Number>(1, 8);
    if (nSegments * sizeof(cmsCurveSegment) <= fdp.remaining_bytes() / 2) {
        std::vector<cmsCurveSegment> segments(nSegments);
        std::vector<std::vector<cmsFloat32Number>> sampledPointsArrays; // Store allocated arrays
        
        for (cmsUInt32Number i = 0; i < nSegments && fdp.remaining_bytes() > 0; i++) {
            segments[i].x0 = fdp.ConsumeFloatingPoint<float>();
            segments[i].x1 = fdp.ConsumeFloatingPoint<float>();
            segments[i].Type = fdp.ConsumeIntegral<cmsInt32Number>();
            
            for (int j = 0; j < 10 && fdp.remaining_bytes() > 0; j++) {
                segments[i].Params[j] = fdp.ConsumeFloatingPoint<double>();
            }
            
            segments[i].nGridPoints = fdp.ConsumeIntegral<cmsUInt32Number>();
            segments[i].SampledPoints = NULL; // Default to NULL
            
            // For sampled segments (Type == 0), we need to allocate and fill SampledPoints
            // If we can't provide valid SampledPoints, change the segment type to avoid crash
            if (segments[i].Type == 0) {
                if (segments[i].nGridPoints > 0 && fdp.remaining_bytes() >= segments[i].nGridPoints * sizeof(cmsFloat32Number)) {
                    // Allocate and fill sampled points array
                    sampledPointsArrays.emplace_back(segments[i].nGridPoints);
                    for (cmsUInt32Number j = 0; j < segments[i].nGridPoints && fdp.remaining_bytes() > 0; j++) {
                        sampledPointsArrays.back()[j] = fdp.ConsumeFloatingPoint<float>();
                    }
                    // Point to the allocated array
                    segments[i].SampledPoints = sampledPointsArrays.back().data();
                } else {
                    // Not enough data for sampled points or nGridPoints is 0
                    // Change to a simple parametric type to avoid NULL SampledPoints crash
                    segments[i].Type = 1; // Identity curve type
                    segments[i].nGridPoints = 0; // Not needed for parametric curves
                    segments[i].SampledPoints = NULL;
                    // Set some reasonable default parameters for identity curve if all zeros
                    // Don't hardcode values - use what was already consumed from fuzzer input
                    // If all params are zero, the library will handle it (might crash, which is fine for fuzzing)
                }
            }
        }
        
        cmsToneCurve* segmentedCurve = cmsBuildSegmentedToneCurve(context, nSegments, segments.data());
        if (segmentedCurve != NULL) {
            curves.push_back(segmentedCurve);
        }
    }
    
    // 2. Manipulate and transform existing curves
    
    // Create a copy of the curves vector to avoid modifying while iterating
    std::vector<cmsToneCurve*> newCurves;
    size_t originalCurveCount = curves.size();
    
    for (size_t i = 0; i < originalCurveCount && fdp.remaining_bytes() > 0; i++) {
        cmsToneCurve* curve = curves[i];
        if (curve == NULL) continue;
        
        // Create duplicate
        cmsToneCurve* dupCurve = cmsDupToneCurve(curve);
        if (dupCurve != NULL) {
            newCurves.push_back(dupCurve);
        }
        
        // Reverse curve
        cmsToneCurve* reversedCurve = cmsReverseToneCurve(curve);
        if (reversedCurve != NULL) {
            newCurves.push_back(reversedCurve);
        }
        
        // Reverse curve with explicit sample count
        if (fdp.remaining_bytes() >= 4) {
            cmsUInt32Number nResultSamples = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 1024);
            cmsToneCurve* reversedExCurve = cmsReverseToneCurveEx(nResultSamples, curve);
            if (reversedExCurve != NULL) {
                newCurves.push_back(reversedExCurve);
            }
        }
        
        // Smooth curve if enough data
        if (fdp.remaining_bytes() >= 8) {
            cmsFloat64Number lambda = fdp.ConsumeFloatingPoint<double>();
            // Note: cmsSmoothToneCurve modifies the curve in-place
            cmsSmoothToneCurve(curve, lambda);
        }
    }
    
    // Add all new curves to the main vector
    curves.insert(curves.end(), newCurves.begin(), newCurves.end());
    
    // 3. Join curves (test pairwise combinations)
    for (size_t i = 0; i < curves.size() && i + 1 < curves.size() && fdp.remaining_bytes() > 0; i += 2) {
        if (fdp.remaining_bytes() >= 4) {
            cmsUInt32Number nPoints = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 256);
            cmsToneCurve* joinedCurve = cmsJoinToneCurve(context, curves[i], curves[i + 1], nPoints);
            if (joinedCurve != NULL) {
                curves.push_back(joinedCurve);
            }
        }
    }
    
    // 4. Evaluate and analyze curves
    for (size_t i = 0; i < curves.size() && fdp.remaining_bytes() > 0; i++) {
        cmsToneCurve* curve = curves[i];
        if (curve == NULL) continue;
        
        // Evaluate with float input
        if (fdp.remaining_bytes() >= 4) {
            cmsFloat32Number floatValue = fdp.ConsumeFloatingPoint<float>();
            cmsEvalToneCurveFloat(curve, floatValue);
        }
        
        // Evaluate with 16-bit input
        if (fdp.remaining_bytes() >= 2) {
            cmsUInt16Number intValue = fdp.ConsumeIntegral<cmsUInt16Number>();
            cmsEvalToneCurve16(curve, intValue);
        }
        
        // Analyze curve properties
        cmsIsToneCurveMultisegment(curve);
        cmsIsToneCurveLinear(curve);
        cmsIsToneCurveMonotonic(curve);
        cmsIsToneCurveDescending(curve);
        
        // Get parametric type
        cmsGetToneCurveParametricType(curve);
        
        // Estimate gamma
        if (fdp.remaining_bytes() >= 8) {
            cmsFloat64Number precision = fdp.ConsumeFloatingPoint<double>();
            cmsEstimateGamma(curve, precision);
        }
        
        // Get curve segment information
        cmsInt32Number segmentIndex = fdp.ConsumeIntegral<cmsInt32Number>();
        cmsGetToneCurveSegment(segmentIndex, curve);
        
        // Get estimated table information
        cmsGetToneCurveEstimatedTableEntries(curve);
        cmsGetToneCurveEstimatedTable(curve);
    }
    
    // 5. Test triple curve operations (for cmsFreeToneCurveTriple)
    if (curves.size() >= 3 && fdp.remaining_bytes() > 0) {
        cmsToneCurve* triple[3] = {curves[0], curves[1], curves[2]};
        
        // Note: cmsFreeToneCurveTriple would free all curves, so we don't call it here
        // since we need to free individually later. But we can test the concept.
        
        // Test cmsStageAllocToneCurves which uses triple arrays
        cmsStage* toneCurveStage = cmsStageAllocToneCurves(context, 3, triple);
        if (toneCurveStage != NULL) {
            cmsStageFree(toneCurveStage);
        }
    }
    
    // 6. Cleanup all curves
    for (size_t i = 0; i < curves.size(); i++) {
        if (curves[i] != NULL) {
            cmsFreeToneCurve(curves[i]);
        }
    }
    
    // Also test cmsFreeToneCurveTriple with a fresh set of curves
    if (fdp.remaining_bytes() > 0) {
        cmsToneCurve* testTriple[3] = {NULL, NULL, NULL};
        
        // Create 3 simple curves for testing
        for (int i = 0; i < 3 && fdp.remaining_bytes() > 0; i++) {
            cmsFloat64Number testGamma = fdp.ConsumeFloatingPoint<double>();
            testTriple[i] = cmsBuildGamma(context, testGamma);
        }
        
        // Free all three at once
        cmsFreeToneCurveTriple(testTriple);
    }
    
    // Clean up context
    cmsDeleteContext(context);
    
    return 0;
}
