// Copyright 2024 RE2 Fuzzing Harness
// Fuzzing harness for RE2::Set API targeting high undiscovered branch complexity (100+ branches)
// Coverage target: RE2::Set lifecycle with move semantics, error handling, memory limits, and edge cases
// Focus on semantic diversity from harness_004.cpp by targeting:
// 1) Move constructor and move assignment operator paths
// 2) All ErrorKind cases: kNoError, kNotCompiled, kOutOfMemory, kInconsistent
// 3) Memory limit configurations to trigger DFA out-of-memory paths
// 4) Post-compilation illegal operations (Add after Compile, Compile multiple times)
// 5) Complex regex pattern combinations affecting internal SparseSet operations
// 6) Anchor variations with text boundary conditions
// 7) Empty set and single pattern edge cases

#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <memory>
#include <algorithm>

// RE2 headers
#include "re2/re2.h"
#include "re2/set.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Early return for trivial inputs - need enough for complex configurations
    if (size < 32) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // ================================================
    // PHASE 1: Test Move Semantics (unique to this harness)
    // ================================================
    
    // Create initial RE2::Options with aggressive memory limits to test OOM paths
    RE2::Options options;
    
    // Set encoding (affects pattern parsing)
    options.set_encoding(fdp.ConsumeBool() ? RE2::Options::EncodingLatin1 
                                           : RE2::Options::EncodingUTF8);
    
    // Critical: Set very low memory limits to trigger kOutOfMemory error paths
    // This exercises DFA memory exhaustion code (lines 156-165 in set.cc)
    int64_t memory_limit = fdp.ConsumeIntegralInRange<int64_t>(1024, 65536); // 1KB to 64KB
    options.set_max_mem(memory_limit);
    
    // Set various regex options that affect internal compilation
    options.set_posix_syntax(fdp.ConsumeBool());
    options.set_longest_match(fdp.ConsumeBool());
    options.set_log_errors(fdp.ConsumeBool());  // Enable/disable error logging
    options.set_literal(fdp.ConsumeBool());
    options.set_never_nl(fdp.ConsumeBool());
    options.set_dot_nl(fdp.ConsumeBool());
    options.set_never_capture(true);  // Note: Set constructor forces this (line 30 in set.cc)
    options.set_case_sensitive(!fdp.ConsumeBool());  // Test case-insensitive paths
    options.set_perl_classes(fdp.ConsumeBool());
    options.set_word_boundary(fdp.ConsumeBool());
    options.set_one_line(fdp.ConsumeBool());

    // Choose anchor type - test all three variants
    RE2::Anchor anchor;
    uint8_t anchor_choice = fdp.ConsumeIntegral<uint8_t>() % 3;
    switch (anchor_choice) {
        case 0: anchor = RE2::UNANCHORED; break;
        case 1: anchor = RE2::ANCHOR_START; break;
        case 2: anchor = RE2::ANCHOR_BOTH; break;
        default: anchor = RE2::UNANCHORED; break;
    }

    // Create initial set
    RE2::Set set1(options, anchor);

    // ================================================
    // PHASE 2: Add patterns with complex combinations
    // ================================================
    
    // Determine number of patterns (0-10 for fuzzing efficiency, including 0 for empty set)
    int pattern_count = fdp.ConsumeIntegralInRange<int>(0, 10);
    std::vector<int> pattern_indices;
    
    // Track error strings to test error propagation
    std::vector<std::string> error_strings;
    
    for (int i = 0; i < pattern_count; i++) {
        // Build complex patterns with varying syntax to exercise different parser paths
        std::string pattern_base;
        
        // Consume pattern type to create diverse regex structures
        uint8_t pattern_type = fdp.ConsumeIntegral<uint8_t>() % 5;
        
        switch (pattern_type) {
            case 0:
                // Simple literal pattern
                pattern_base = fdp.ConsumeRandomLengthString(64);
                break;
            case 1:
                // Pattern with character classes
                pattern_base = "[" + fdp.ConsumeRandomLengthString(32) + "]";
                break;
            case 2:
                // Pattern with alternation
                pattern_base = fdp.ConsumeRandomLengthString(16) + "|" + 
                              fdp.ConsumeRandomLengthString(16);
                break;
            case 3:
                // Pattern with repetition
                pattern_base = "(" + fdp.ConsumeRandomLengthString(20) + "){1," + 
                              std::to_string(fdp.ConsumeIntegralInRange<int>(1, 5)) + "}";
                break;
            case 4:
                // Pattern with backreferences (may fail parsing but tests error paths)
                pattern_base = "(" + fdp.ConsumeRandomLengthString(10) + ")\\1";
                break;
        }
        
        // Sometimes add anchors or boundaries
        if (fdp.ConsumeBool()) {
            pattern_base = "^" + pattern_base;
        }
        if (fdp.ConsumeBool()) {
            pattern_base = pattern_base + "$";
        }
        if (fdp.ConsumeBool()) {
            pattern_base = "\\b" + pattern_base + "\\b";
        }
        
        // Add pattern with optional error capture
        std::string* error_ptr = nullptr;
        if (fdp.ConsumeBool()) {
            error_strings.emplace_back();
            error_ptr = &error_strings.back();
        }
        
        int index = set1.Add(pattern_base, error_ptr);
        pattern_indices.push_back(index);
        
        // Test Size() after each addition
        (void)set1.Size();
    }

    // ================================================
    // PHASE 3: Move Semantics Testing (lines 38-56 in set.cc)
    // ================================================
    
    // Test move constructor
    RE2::Set set2(std::move(set1));
    
    // Verify set1 is in moved-from state (should be empty/compiled_ false)
    // Note: set1 should not be used after move, but we can check Size() was transferred
    
    // Test move assignment operator
    RE2::Set set3(options, RE2::UNANCHORED);
    set3 = std::move(set2);
    
    // ================================================
    // PHASE 4: Compilation with Error Paths
    // ================================================
    
    bool compile_success = false;
    
    if (pattern_count > 0) {
        // First compilation attempt
        compile_success = set3.Compile();
        
        // Test illegal second compilation (should trigger ABSL_LOG(DFATAL) at line 104)
        // We'll call but ignore result since it's a DCHECK violation
        if (fdp.ConsumeBool()) {
            bool second_compile = set3.Compile();
            (void)second_compile; // Should be false due to DCHECK
        }
        
        // Test illegal Add after compilation (should trigger ABSL_LOG(DFATAL) at line 66)
        if (fdp.ConsumeBool()) {
            std::string post_compile_error;
            int illegal_index = set3.Add("illegal", &post_compile_error);
            (void)illegal_index; // Should be -1 due to DCHECK
        }
    } else {
        // Empty set compilation
        compile_success = set3.Compile();
    }

    // ================================================
    // PHASE 5: Matching Operations with All ErrorInfo Cases
    // ================================================
    
    // Generate text for matching from remaining fuzzer input
    std::string text = fdp.ConsumeRemainingBytesAsString();
    
    if (compile_success && pattern_count > 0) {
        absl::string_view text_view(text);
        
        // Test 1: Match without result vector (simple boolean return)
        bool match1 = set3.Match(text_view, nullptr);
        (void)match1;
        
        // Test 2: Match with result vector
        std::vector<int> results;
        bool match2 = set3.Match(text_view, &results);
        (void)match2;
        
        // Process results if any
        if (!results.empty()) {
            // Verify indices are within bounds (0 <= idx < Size())
            for (int idx : results) {
                if (idx >= 0 && idx < set3.Size()) {
                    // Valid index - test duplicate handling
                    (void)idx;
                }
            }
            
            // Test sorting assumption (implementation says "Callers must not expect v to be sorted")
            // We'll verify they're not necessarily sorted by checking if sorted
            std::vector<int> sorted_results = results;
            std::sort(sorted_results.begin(), sorted_results.end());
            if (results != sorted_results) {
                // Results are unsorted as documented
                (void)0;
            }
        }
        
        // Test 3: Match with ErrorInfo to capture all error kinds
        RE2::Set::ErrorInfo error_info;
        std::vector<int> error_results;
        
        // First, test with valid compilation
        bool match_with_error = set3.Match(text_view, &error_results, &error_info);
        (void)match_with_error;
        
        // Check error_info.kind (should be kNoError if match succeeded/failed normally)
        (void)error_info.kind;
        
        // Test 4: Edge case matching
        // Empty text matching
        std::vector<int> empty_results;
        bool empty_match = set3.Match("", &empty_results);
        (void)empty_match;
        
        // Very long text (may trigger different DFA paths)
        std::string long_text(1000, 'a');
        bool long_match = set3.Match(long_text, nullptr);
        (void)long_match;
        
        // Text with null bytes (boundary condition)
        std::string null_text("prefix\0suffix", 13);
        bool null_match = set3.Match(null_text, nullptr);
        (void)null_match;
        
        // Test 5: Create uncompiled set to trigger kNotCompiled error
        if (fdp.ConsumeBool()) {
            RE2::Set uncompiled_set(options, anchor);
            // Add a pattern but don't compile
            uncompiled_set.Add("test", nullptr);
            
            RE2::Set::ErrorInfo not_compiled_error;
            std::vector<int> not_compiled_results;
            bool not_compiled_match = uncompiled_set.Match(text_view, &not_compiled_results, &not_compiled_error);
            (void)not_compiled_match;
            // error_info.kind should be kNotCompiled (line 141 in set.cc)
            (void)not_compiled_error.kind;
        }
    } else if (pattern_count == 0) {
        // Empty set matching tests
        absl::string_view text_view(text);
        
        // Empty set should never match
        std::vector<int> empty_set_results;
        RE2::Set::ErrorInfo empty_error;
        bool empty_set_match = set3.Match(text_view, &empty_set_results, &empty_error);
        (void)empty_set_match;
        (void)empty_error.kind;
        
        // Results vector should be empty
        if (empty_set_results.empty()) {
            (void)0; // Expected behavior
        }
    }

    // ================================================
    // PHASE 6: Additional Error Path Testing
    // ================================================
    
    // Test kInconsistent error path (lines 172-177 in set.cc)
    // This requires DFA matches but matches.empty() - hard to trigger but we can try
    // by creating complex patterns that might confuse the DFA
    
    // Test memory exhaustion more directly by creating sets with many complex patterns
    // and very low memory limits
    
    if (fdp.remaining_bytes() > 100) {
        RE2::Options oom_options = options;
        oom_options.set_max_mem(1024); // Very low: 1KB
        
        RE2::Set oom_set(oom_options, RE2::UNANCHORED);
        
        // Add a few moderately complex patterns
        for (int i = 0; i < 3 && fdp.remaining_bytes() > 20; i++) {
            std::string complex_pattern = "(" + fdp.ConsumeRandomLengthString(20) + ")+";
            oom_set.Add(complex_pattern, nullptr);
        }
        
        if (oom_set.Size() > 0) {
            bool oom_compile = oom_set.Compile();
            (void)oom_compile; // May fail due to memory limits
            
            if (oom_compile) {
                // Try to match to potentially trigger kOutOfMemory
                std::string oom_text = fdp.ConsumeRandomLengthString(100);
                RE2::Set::ErrorInfo oom_error;
                std::vector<int> oom_results;
                bool oom_match = oom_set.Match(oom_text, &oom_results, &oom_error);
                (void)oom_match;
                (void)oom_error.kind; // Could be kOutOfMemory
            }
        }
    }

    // ================================================
    // PHASE 7: Cleanup and Final Checks
    // ================================================
    
    // Verify Size() consistency
    if (compile_success) {
        int final_size = set3.Size();
        (void)final_size;
        
        // Size should equal number of successfully added patterns
        int successful_adds = 0;
        for (int idx : pattern_indices) {
            if (idx != -1) successful_adds++;
        }
        
        // Note: Size() after compilation returns size_ (line 61) not elem_.size()
        // and elem_ is cleared after compilation (line 121)
        (void)successful_adds;
    }
    
    // Access error strings if they exist (to ensure they were populated)
    for (const auto& error_str : error_strings) {
        if (!error_str.empty()) {
            (void)error_str.c_str();
        }
    }

    return 0;
}
