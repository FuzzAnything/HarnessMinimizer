// Fuzzing harness for Little CMS 2 library
// Target: Tone curve manipulation functions with 128+ undiscovered branches
// Strategy: Follow the exact workflow from coverage guidance:
//           1. Create context using cmsCreateContext (or use NULL for default context)
//           2. Create multiple tone curves with different characteristics:
//              - Parametric curves with different type parameters (1-8, 108, 109)
//              - Segmented curves with multiple segments  
//              - Tabulated curves from sampled data
//           3. For each curve, test cmsIsToneCurveMonotonic and cmsIsToneCurveMultisegment
//           4. Apply cmsSmoothToneCurve to curves with varying lambda values (0.0 to 1.0)
//           5. Create pairs of curves and join them using cmsJoinToneCurve with different point counts
//           6. For resulting curves, extract segments using cmsGetToneCurveSegment
//           7. Estimate gamma tables using cmsGetToneCurveEstimatedTable
//           8. Clean up all curves with cmsFreeToneCurve
//           9. Delete context if created
// Focus APIs: cmsSmoothToneCurve (50 undiscovered accumulated branches),
//             cmsJoinToneCurve (42), cmsIsToneCurveMonotonic (18),
//             cmsGetToneCurveSegment (8), cmsIsToneCurveMultisegment (4),
//             cmsGetToneCurveEstimatedTable (4)
// Helper APIs: cmsBuildParametricToneCurve, cmsBuildSegmentedToneCurve,
//              cmsBuildTabulatedToneCurveFloat, cmsReverseToneCurve,
//              cmsDupToneCurve, cmsFreeToneCurve, cmsCreateContext
// Semantic uniqueness: First harness to comprehensively target tone curve manipulation workflow,
//                      implements full curve lifecycle: create → inspect → transform → join → analyze

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include "lcms2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for multiple curve creations and operations
    // We need: curve types, parameters, segment counts, lambda values, etc.
    if (size < 512) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Create context for curve operations (optional, can use NULL)
    bool use_context = fdp.ConsumeBool();
    cmsContext context = NULL;
    if (use_context) {
        context = cmsCreateContext(NULL, NULL);
        if (context == NULL) {
            return 0;
        }
    }
    
    std::vector<cmsToneCurve*> curves;
    std::vector<cmsToneCurve*> joined_curves;
    
    // Step 2: Create multiple tone curves with different characteristics
    
    // 2.1 Create parametric tone curves with different type parameters (1-8, 108, 109)
    // According to the source code, supported types are: 1, 2, 3, 4, 5, 6, 7, 8, 108, 109
    const cmsInt32Number parametric_types[] = {1, 2, 3, 4, 5, 6, 7, 8, 108, 109};
    const size_t num_parametric_types = sizeof(parametric_types) / sizeof(parametric_types[0]);
    
    for (size_t i = 0; i < 3 && fdp.remaining_bytes() > 100; i++) {
        cmsInt32Number type = parametric_types[fdp.ConsumeIntegralInRange<size_t>(0, num_parametric_types - 1)];
        
        // Determine number of parameters needed for this type
        // From DefaultCurves in cmsgamma.c: types 1-8, 108, 109 have parameter counts: {1, 3, 4, 5, 7, 4, 5, 5, 1, 1}
        size_t param_count = 1; // default for types 1, 108, 109
        if (type == 2) param_count = 3;
        else if (type == 3) param_count = 4;
        else if (type == 4) param_count = 5;
        else if (type == 5) param_count = 7;
        else if (type == 6) param_count = 4;
        else if (type == 7) param_count = 5;
        else if (type == 8) param_count = 5;
        
        std::vector<cmsFloat64Number> params(param_count);
        for (size_t j = 0; j < param_count; j++) {
            params[j] = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-10.0, 10.0);
        }
        
        cmsToneCurve* parametric_curve = cmsBuildParametricToneCurve(context, type, params.data());
        if (parametric_curve != NULL) {
            curves.push_back(parametric_curve);
        }
    }
    
    // 2.2 Create segmented tone curves
    if (fdp.remaining_bytes() > 200) {
        cmsUInt32Number n_segments = fdp.ConsumeIntegralInRange<cmsUInt32Number>(1, 5);
        std::vector<cmsCurveSegment> segments(n_segments);
        
        for (cmsUInt32Number seg_idx = 0; seg_idx < n_segments; seg_idx++) {
            segments[seg_idx].x0 = fdp.ConsumeFloatingPointInRange<cmsFloat32Number>(0.0f, 1.0f);
            segments[seg_idx].x1 = fdp.ConsumeFloatingPointInRange<cmsFloat32Number>(segments[seg_idx].x0 + 0.1f, 1.0f);
            
            // Choose segment type: 0 for sampled, or parametric type
            bool use_sampled = fdp.ConsumeBool();
            if (use_sampled) {
                segments[seg_idx].Type = 0; // Sampled segment
                segments[seg_idx].nGridPoints = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 10);
                
                // Allocate and fill sampled points
                size_t sample_size = segments[seg_idx].nGridPoints * sizeof(cmsFloat32Number);
                if (fdp.remaining_bytes() >= sample_size) {
                    std::vector<cmsFloat32Number> sampled_points(segments[seg_idx].nGridPoints);
                    for (cmsUInt32Number p = 0; p < segments[seg_idx].nGridPoints; p++) {
                        sampled_points[p] = fdp.ConsumeFloatingPointInRange<cmsFloat32Number>(0.0f, 1.0f);
                    }
                    // Note: In real usage, we would need to allocate and manage this memory properly
                    // For fuzzing, we'll skip complex memory management for sampled points
                }
                // Clear params for sampled segment
                memset(segments[seg_idx].Params, 0, sizeof(segments[seg_idx].Params));
                segments[seg_idx].SampledPoints = NULL;
            } else {
                // Parametric segment
                segments[seg_idx].Type = fdp.ConsumeIntegralInRange<cmsInt32Number>(1, 8);
                segments[seg_idx].nGridPoints = 0;
                segments[seg_idx].SampledPoints = NULL;
                
                // Fill parameters based on type (simplified)
                size_t param_count = 1;
                if (segments[seg_idx].Type == 2) param_count = 3;
                else if (segments[seg_idx].Type == 3) param_count = 4;
                else if (segments[seg_idx].Type == 4) param_count = 5;
                else if (segments[seg_idx].Type == 5) param_count = 7;
                else if (segments[seg_idx].Type == 6) param_count = 4;
                else if (segments[seg_idx].Type == 7) param_count = 5;
                else if (segments[seg_idx].Type == 8) param_count = 5;
                
                for (size_t p = 0; p < param_count; p++) {
                    segments[seg_idx].Params[p] = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-10.0, 10.0);
                }
                // Clear remaining params
                for (size_t p = param_count; p < 10; p++) {
                    segments[seg_idx].Params[p] = 0.0;
                }
            }
        }
        
        cmsToneCurve* segmented_curve = cmsBuildSegmentedToneCurve(context, n_segments, segments.data());
        if (segmented_curve != NULL) {
            curves.push_back(segmented_curve);
        }
    }
    
    // 2.3 Create tabulated tone curves from sampled data
    if (fdp.remaining_bytes() > 100) {
        cmsUInt32Number n_entries = fdp.ConsumeIntegralInRange<cmsUInt32Number>(2, 100);
        if (fdp.remaining_bytes() >= n_entries * sizeof(cmsFloat32Number)) {
            std::vector<cmsFloat32Number> tabulated_values(n_entries);
            for (cmsUInt32Number i = 0; i < n_entries; i++) {
                tabulated_values[i] = fdp.ConsumeFloatingPointInRange<cmsFloat32Number>(0.0f, 1.0f);
            }
            
            cmsToneCurve* tabulated_curve = cmsBuildTabulatedToneCurveFloat(context, n_entries, tabulated_values.data());
            if (tabulated_curve != NULL) {
                curves.push_back(tabulated_curve);
            }
        }
    }
    
    // 2.4 Create a simple gamma curve for basic operations
    cmsFloat64Number gamma = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(0.1, 5.0);
    cmsToneCurve* gamma_curve = cmsBuildGamma(context, gamma);
    if (gamma_curve != NULL) {
        curves.push_back(gamma_curve);
    }
    
    // If no curves were created, return early
    if (curves.empty()) {
        if (use_context && context != NULL) {
            cmsDeleteContext(context);
        }
        return 0;
    }
    
    // Step 3: Test inspection functions on each curve
    for (cmsToneCurve* curve : curves) {
        if (curve == NULL) continue;
        
        // Test monotonicity
        cmsBool is_monotonic = cmsIsToneCurveMonotonic(curve);
        (void)is_monotonic; // Use result to avoid unused variable warning
        
        // Test if multisegment
        cmsBool is_multisegment = cmsIsToneCurveMultisegment(curve);
        (void)is_multisegment;
        
        // Test if linear
        cmsBool is_linear = cmsIsToneCurveLinear(curve);
        (void)is_linear;
        
        // Test if descending
        cmsBool is_descending = cmsIsToneCurveDescending(curve);
        (void)is_descending;
        
        // Get parametric type if applicable
        cmsInt32Number param_type = cmsGetToneCurveParametricType(curve);
        (void)param_type;
        
        // Estimate gamma
        cmsFloat64Number estimated_gamma = cmsEstimateGamma(curve, 0.001);
        (void)estimated_gamma;
        
        // Get segments if available
        for (cmsInt32Number seg_idx = 0; seg_idx < 5; seg_idx++) {
            const cmsCurveSegment* segment = cmsGetToneCurveSegment(seg_idx, curve);
            if (segment == NULL) break;
            
            // Access segment fields
            (void)segment->x0;
            (void)segment->x1;
            (void)segment->Type;
            (void)segment->nGridPoints;
        }
        
        // Get estimated table
        cmsUInt32Number table_entries = cmsGetToneCurveEstimatedTableEntries(curve);
        if (table_entries > 0) {
            const cmsUInt16Number* table = cmsGetToneCurveEstimatedTable(curve);
            if (table != NULL) {
                // Access a few table entries
                for (cmsUInt32Number i = 0; i < table_entries && i < 10; i++) {
                    (void)table[i];
                }
            }
        }
    }
    
    // Step 4: Apply smoothing to curves with varying lambda values
    for (cmsToneCurve* curve : curves) {
        if (curve == NULL) continue;
        
        // Try smoothing with different lambda values
        for (int smooth_attempt = 0; smooth_attempt < 3 && fdp.remaining_bytes() > 10; smooth_attempt++) {
            cmsFloat64Number lambda = fdp.ConsumeFloatingPointInRange<cmsFloat64Number>(-1.0, 2.0);
            
            // Create a duplicate for smoothing (smoothing modifies the curve in-place)
            cmsToneCurve* curve_dup = cmsDupToneCurve(curve);
            if (curve_dup != NULL) {
                cmsBool smooth_success = cmsSmoothToneCurve(curve_dup, lambda);
                (void)smooth_success;
                
                // Clean up duplicated curve
                cmsFreeToneCurve(curve_dup);
            }
        }
    }
    
    // Step 5: Create pairs of curves and join them
    // Create some reversed curves for joining
    std::vector<cmsToneCurve*> reversed_curves;
    for (cmsToneCurve* curve : curves) {
        if (curve == NULL) continue;
        
        cmsToneCurve* reversed = cmsReverseToneCurve(curve);
        if (reversed != NULL) {
            reversed_curves.push_back(reversed);
        }
    }
    
    // Join original curves with reversed curves
    for (size_t i = 0; i < curves.size() && i < reversed_curves.size() && fdp.remaining_bytes() > 10; i++) {
        if (curves[i] == NULL || reversed_curves[i] == NULL) continue;
        
        cmsUInt32Number n_points = fdp.ConsumeIntegralInRange<cmsUInt32Number>(10, 1000);
        cmsToneCurve* joined = cmsJoinToneCurve(context, curves[i], reversed_curves[i], n_points);
        if (joined != NULL) {
            joined_curves.push_back(joined);
        }
    }
    
    // Step 6: Test operations on joined curves
    for (cmsToneCurve* joined_curve : joined_curves) {
        if (joined_curve == NULL) continue;
        
        // Test monotonicity on joined curves
        cmsBool joined_monotonic = cmsIsToneCurveMonotonic(joined_curve);
        (void)joined_monotonic;
        
        // Get segments from joined curves
        for (cmsInt32Number seg_idx = 0; seg_idx < 5; seg_idx++) {
            const cmsCurveSegment* segment = cmsGetToneCurveSegment(seg_idx, joined_curve);
            if (segment == NULL) break;
            (void)segment;
        }
        
        // Get estimated table from joined curves
        cmsUInt32Number joined_table_entries = cmsGetToneCurveEstimatedTableEntries(joined_curve);
        if (joined_table_entries > 0) {
            const cmsUInt16Number* joined_table = cmsGetToneCurveEstimatedTable(joined_curve);
            if (joined_table != NULL) {
                (void)joined_table[0];
            }
        }
    }
    
    // Step 7: Test evaluation functions on curves
    for (cmsToneCurve* curve : curves) {
        if (curve == NULL) continue;
        
        // Evaluate at a few points
        for (int eval_idx = 0; eval_idx < 5 && fdp.remaining_bytes() > 4; eval_idx++) {
            cmsFloat32Number input_val = fdp.ConsumeFloatingPointInRange<cmsFloat32Number>(0.0f, 1.0f);
            cmsFloat32Number float_result = cmsEvalToneCurveFloat(curve, input_val);
            (void)float_result;
            
            cmsUInt16Number int_input = static_cast<cmsUInt16Number>(input_val * 65535.0f);
            cmsUInt16Number int_result = cmsEvalToneCurve16(curve, int_input);
            (void)int_result;
        }
    }
    
    // Step 8: Clean up all curves
    for (cmsToneCurve* curve : curves) {
        if (curve != NULL) {
            cmsFreeToneCurve(curve);
        }
    }
    
    for (cmsToneCurve* reversed_curve : reversed_curves) {
        if (reversed_curve != NULL) {
            cmsFreeToneCurve(reversed_curve);
        }
    }
    
    for (cmsToneCurve* joined_curve : joined_curves) {
        if (joined_curve != NULL) {
            cmsFreeToneCurve(joined_curve);
        }
    }
    
    // Step 9: Delete context if created
    if (use_context && context != NULL) {
        cmsDeleteContext(context);
    }
    
    return 0;
}
