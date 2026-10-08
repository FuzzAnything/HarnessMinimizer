// Copyright 2024 Fuzzing Harness Generator
// Harness 008 for RE2 library - targeting FilteredRE2 operations to cover critical coverage gaps
// Based on coverage guidance: FilteredRE2 module has 22 undiscovered branches across key APIs
// APIs: FilteredRE2::Add (7/10 undiscovered), FilteredRE2::Compile (8/12), FilteredRE2::FirstMatch (7/12)

#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>

#include "re2/re2.h"
#include "re2/filtered_re2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need substantial input for complex regex patterns, options, and test strings
    if (size < 128) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Create FilteredRE2 objects with different constructors
    // Test both default constructor and constructor with min_atom_len
    std::unique_ptr<re2::FilteredRE2> filtered_re2_default;
    std::unique_ptr<re2::FilteredRE2> filtered_re2_minlen;
    
    int constructor_choice = fdp.ConsumeIntegralInRange<int>(0, 2);
    switch (constructor_choice) {
        case 0:
            filtered_re2_default = std::make_unique<re2::FilteredRE2>();
            break;
        case 1: {
            int min_atom_len = fdp.ConsumeIntegralInRange<int>(1, 8);
            filtered_re2_minlen = std::make_unique<re2::FilteredRE2>(min_atom_len);
            break;
        }
        case 2:
            // Create both for comprehensive testing
            filtered_re2_default = std::make_unique<re2::FilteredRE2>();
            filtered_re2_minlen = std::make_unique<re2::FilteredRE2>(
                fdp.ConsumeIntegralInRange<int>(1, 8));
            break;
    }
    
    re2::FilteredRE2* primary_filter = nullptr;
    if (filtered_re2_default) {
        primary_filter = filtered_re2_default.get();
    } else if (filtered_re2_minlen) {
        primary_filter = filtered_re2_minlen.get();
    }
    
    if (!primary_filter) {
        return 0;
    }
    
    // Step 2: Create RE2::Options with various configurations
    re2::RE2::Options options;
    
    // Test different encoding combinations (Latin1 vs UTF-8)
    switch (fdp.ConsumeIntegralInRange<int>(0, 2)) {
        case 0: options.set_encoding(re2::RE2::Options::EncodingLatin1); break;
        case 1: options.set_encoding(re2::RE2::Options::EncodingUTF8); break;
        case 2: 
            // Random encoding based on bool
            if (fdp.ConsumeBool()) {
                options.set_encoding(re2::RE2::Options::EncodingLatin1);
            } else {
                options.set_encoding(re2::RE2::Options::EncodingUTF8);
            }
            break;
    }
    
    // Set various flags that affect pattern compilation and matching
    options.set_case_sensitive(!fdp.ConsumeBool());
    options.set_posix_syntax(fdp.ConsumeBool());
    options.set_literal(fdp.ConsumeBool());
    options.set_never_nl(fdp.ConsumeBool());
    options.set_dot_nl(fdp.ConsumeBool());
    options.set_never_capture(fdp.ConsumeBool());
    options.set_perl_classes(fdp.ConsumeBool());
    options.set_word_boundary(fdp.ConsumeBool());
    options.set_one_line(fdp.ConsumeBool());
    options.set_longest_match(fdp.ConsumeBool());
    options.set_log_errors(false); // Disable error logging for fuzzing
    options.set_max_mem(64 << 20); // 64MB memory limit
    
    // Step 3: Add regex patterns to FilteredRE2
    // Determine number of patterns to add (0-10 to test empty pattern list)
    int num_patterns = fdp.ConsumeIntegralInRange<int>(0, 10);
    std::vector<int> pattern_ids;
    std::vector<std::string> patterns_added;
    
    for (int i = 0; i < num_patterns && fdp.remaining_bytes() > 32; i++) {
        // Generate different types of regex patterns
        int pattern_type = fdp.ConsumeIntegralInRange<int>(0, 8);
        std::string pattern;
        bool use_options = fdp.ConsumeBool();
        
        switch (pattern_type) {
            case 0: // Simple literal patterns
                pattern = fdp.ConsumeRandomLengthString(32);
                break;
                
            case 1: // Character classes
                {
                    std::string chars = fdp.ConsumeRandomLengthString(16);
                    if (!chars.empty()) {
                        bool negated = fdp.ConsumeBool();
                        if (negated) pattern = "[^";
                        else pattern = "[";
                        
                        if (chars.size() >= 2 && fdp.ConsumeBool()) {
                            pattern += chars[0];
                            pattern += '-';
                            pattern += chars[1];
                            if (chars.size() >= 3) {
                                pattern += chars.substr(2, std::min(chars.size()-2, size_t(6)));
                            }
                        } else {
                            pattern += chars.substr(0, std::min(chars.size(), size_t(8)));
                        }
                        pattern += "]";
                    } else {
                        pattern = "[a-z]";
                    }
                }
                break;
                
            case 2: // Alternations (|)
                {
                    std::string part1 = fdp.ConsumeRandomLengthString(12);
                    std::string part2 = fdp.ConsumeRandomLengthString(12);
                    if (!part1.empty() && !part2.empty()) {
                        pattern = "(" + part1 + "|" + part2 + ")";
                    } else {
                        pattern = "(foo|bar|baz)";
                    }
                }
                break;
                
            case 3: // Repetitions (*, +, ?, {})
                {
                    std::string base = fdp.ConsumeRandomLengthString(12);
                    if (!base.empty()) {
                        int rep_type = fdp.ConsumeIntegralInRange<int>(0, 4);
                        switch (rep_type) {
                            case 0: pattern = base + "*"; break;
                            case 1: pattern = base + "+"; break;
                            case 2: pattern = base + "?"; break;
                            case 3: pattern = base + "{1,3}"; break;
                            case 4: pattern = base + "{2}"; break;
                        }
                    } else {
                        pattern = "a{1,3}";
                    }
                }
                break;
                
            case 4: // Anchors (^, $)
                pattern = "^" + fdp.ConsumeRandomLengthString(16) + "$";
                break;
                
            case 5: // Dot and wildcards
                pattern = fdp.ConsumeRandomLengthString(8) + "." + fdp.ConsumeRandomLengthString(8);
                break;
                
            case 6: // Escaped sequences
                pattern = "\\w+\\d{1,4}\\s*" + fdp.ConsumeRandomLengthString(8);
                break;
                
            case 7: // Complex combined patterns
                {
                    std::string part1 = fdp.ConsumeRandomLengthString(6);
                    std::string part2 = fdp.ConsumeRandomLengthString(6);
                    pattern = "(" + part1 + "[a-z]{" + std::to_string(fdp.ConsumeIntegralInRange<int>(1, 5)) + 
                             "}|" + part2 + "\\d+)";
                }
                break;
                
            case 8: // Potentially invalid patterns to test error handling
                if (fdp.ConsumeBool()) {
                    // Generate malformed pattern
                    pattern = fdp.ConsumeRandomLengthString(24);
                    // Inject potential issues
                    if (pattern.size() > 4) {
                        size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, pattern.size()-1);
                        pattern.insert(pos, "[");
                    }
                } else {
                    pattern = fdp.ConsumeRandomLengthString(32);
                }
                break;
        }
        
        if (pattern.empty()) {
            pattern = "test" + std::to_string(i);
        }
        
        // Add pattern to FilteredRE2
        int pattern_id = -1;
        re2::RE2::ErrorCode error_code;
        
        if (use_options) {
            error_code = primary_filter->Add(pattern, options, &pattern_id);
        } else {
            // Use default options
            re2::RE2::Options default_opts;
            default_opts.set_log_errors(false);
            error_code = primary_filter->Add(pattern, default_opts, &pattern_id);
        }
        
        // Store pattern info
        patterns_added.push_back(pattern);
        if (pattern_id != -1) {
            pattern_ids.push_back(pattern_id);
        }
        
        // Test duplicate patterns (advanced scenario from guidance)
        if (fdp.ConsumeBool() && !pattern.empty() && fdp.remaining_bytes() > 16) {
            int dup_id = -1;
            primary_filter->Add(pattern, options, &dup_id);
        }
    }
    
    // Step 4: Compile the FilteredRE2
    std::vector<std::string> atoms;
    primary_filter->Compile(&atoms);
    
    // Step 5: Test matching operations
    if (!atoms.empty() && fdp.remaining_bytes() > 16) {
        // Create atom indices for matching (simulate string matching engine)
        std::vector<int> atom_indices;
        for (size_t i = 0; i < atoms.size() && i < 10; i++) {
            if (fdp.ConsumeBool()) {
                atom_indices.push_back(i);
            }
        }
        
        // If no atom indices selected, add some default ones
        if (atom_indices.empty() && !atoms.empty()) {
            atom_indices.push_back(0);
            if (atoms.size() > 1) atom_indices.push_back(atoms.size() - 1);
        }
        
        // Generate test strings for matching
        int num_test_strings = fdp.ConsumeIntegralInRange<int>(1, 5);
        for (int i = 0; i < num_test_strings && fdp.remaining_bytes() > 32; i++) {
            std::string test_string = fdp.ConsumeRandomLengthString(64);
            
            if (test_string.empty()) {
                test_string = "test" + std::to_string(i) + "123";
            }
            
            // Test FirstMatch
            int first_match_result = primary_filter->FirstMatch(test_string, atom_indices);
            (void)first_match_result; // Use result to avoid unused warning
            
            // Test AllMatches
            std::vector<int> matching_regexps;
            bool all_matches_result = primary_filter->AllMatches(test_string, atom_indices, &matching_regexps);
            (void)all_matches_result;
            
            // Test SlowFirstMatch (can be called without Compile)
            int slow_match_result = primary_filter->SlowFirstMatch(test_string);
            (void)slow_match_result;
            
            // Test AllPotentials
            std::vector<int> potential_regexps;
            primary_filter->AllPotentials(atom_indices, &potential_regexps);
        }
    } else {
        // Test with empty atom indices (edge case)
        std::vector<int> empty_atom_indices;
        std::string test_string = fdp.ConsumeRandomLengthString(32);
        if (!test_string.empty()) {
            int first_match_result = primary_filter->FirstMatch(test_string, empty_atom_indices);
            (void)first_match_result;
            
            std::vector<int> matching_regexps;
            bool all_matches_result = primary_filter->AllMatches(test_string, empty_atom_indices, &matching_regexps);
            (void)all_matches_result;
            
            // Test SlowFirstMatch without compilation
            int slow_match_result = primary_filter->SlowFirstMatch(test_string);
            (void)slow_match_result;
        }
    }
    
    // Step 6: Test move operations (completely uncovered API from guidance)
    if (filtered_re2_default && filtered_re2_minlen && fdp.ConsumeBool()) {
        // Test move constructor
        re2::FilteredRE2 moved_filter(std::move(*filtered_re2_default));
        (void)moved_filter;
        
        // Test move assignment (completely uncovered per guidance)
        if (fdp.ConsumeBool()) {
            *filtered_re2_minlen = std::move(moved_filter);
        }
    }
    
    // Step 7: Additional tests with different option sets
    if (fdp.remaining_bytes() > 64) {
        // Create another FilteredRE2 with different options
        re2::RE2::Options alt_options;
        alt_options.set_encoding(fdp.ConsumeBool() ? 
                                re2::RE2::Options::EncodingLatin1 : 
                                re2::RE2::Options::EncodingUTF8);
        alt_options.set_case_sensitive(!fdp.ConsumeBool());
        alt_options.set_log_errors(false);
        
        re2::FilteredRE2 alt_filter;
        int alt_id = -1;
        
        // Add a few patterns
        int alt_num_patterns = fdp.ConsumeIntegralInRange<int>(1, 3);
        for (int i = 0; i < alt_num_patterns && fdp.remaining_bytes() > 16; i++) {
            std::string alt_pattern = fdp.ConsumeRandomLengthString(24);
            if (!alt_pattern.empty()) {
                alt_filter.Add(alt_pattern, alt_options, &alt_id);
            }
        }
        
        // Compile and test
        std::vector<std::string> alt_atoms;
        alt_filter.Compile(&alt_atoms);
        
        if (!alt_atoms.empty() && fdp.remaining_bytes() > 16) {
            std::vector<int> alt_atom_indices;
            for (size_t i = 0; i < alt_atoms.size() && i < 3; i++) {
                if (fdp.ConsumeBool()) alt_atom_indices.push_back(i);
            }
            
            if (!alt_atom_indices.empty()) {
                std::string alt_test_string = fdp.ConsumeRandomLengthString(32);
                if (!alt_test_string.empty()) {
                    int alt_first_match = alt_filter.FirstMatch(alt_test_string, alt_atom_indices);
                    (void)alt_first_match;
                    
                    std::vector<int> alt_matches;
                    bool alt_all_matches = alt_filter.AllMatches(alt_test_string, alt_atom_indices, &alt_matches);
                    (void)alt_all_matches;
                }
            }
        }
    }
    
    // Step 8: Test NumRegexps and GetRE2 accessors
    int num_regexps = primary_filter->NumRegexps();
    (void)num_regexps;
    
    if (!pattern_ids.empty() && fdp.remaining_bytes() > 0) {
        // Access individual RE2 objects
        for (size_t i = 0; i < pattern_ids.size() && i < 3; i++) {
            const re2::RE2& re2_obj = primary_filter->GetRE2(pattern_ids[i]);
            (void)re2_obj;
        }
    }
    
    // Destructors will automatically clean up
    
    return 0;
}
