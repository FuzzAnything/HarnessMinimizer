// This fuzz driver is generated for library re2, aiming to fuzz the following functions:
// re2::RE2::Match at re2.cc:658:11 in re2.h
// re2::RE2::FindAndConsume at re2.h:463:15 in re2.h
// re2::RE2::FindAndConsume at re2.h:463:15 in re2.h
// re2::RE2::FindAndConsume at re2.h:463:15 in re2.h
// re2::RE2::FullMatchN at re2.cc:418:11 in re2.h
// re2::RE2::FullMatchN at re2.cc:418:11 in re2.h
// re2::RE2::Match at re2.cc:658:11 in re2.h
// re2::RE2::ConsumeN at re2.cc:428:11 in re2.h
// re2::RE2::PartialMatchN at re2.cc:423:11 in re2.h
// re2::RE2::FullMatchN at re2.cc:418:11 in re2.h
// re2::RE2::Options::set_max_mem at re2.h:697:10 in re2.h
// re2::RE2::NumberOfCapturingGroups at re2.h:551:7 in re2.h
// re2::RE2::ok at re2.h:307:8 in re2.h
// re2::RE2::ConsumeN at re2.cc:428:11 in re2.h
// re2::RE2::ConsumeN at re2.cc:428:11 in re2.h
// re2::RE2::PartialMatchN at re2.cc:423:11 in re2.h
// re2::RE2::PartialMatchN at re2.cc:423:11 in re2.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "re2/re2.h"

static absl::string_view MakeStringView(const uint8_t* data, size_t size) {
    if (size == 0) return absl::string_view();
    return absl::string_view(reinterpret_cast<const char*>(data), size);
}

static std::string MakeString(const uint8_t* data, size_t size) {
    if (size == 0) return std::string();
    return std::string(reinterpret_cast<const char*>(data), size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    
    // Split input into pattern and text parts
    size_t pattern_len = Data[0] % Size;
    if (pattern_len == 0) pattern_len = 1;
    if (pattern_len >= Size) pattern_len = Size / 2;
    
    size_t text_len = Size - pattern_len;
    const uint8_t* pattern_data = Data;
    const uint8_t* text_data = Data + pattern_len;
    
    std::string pattern = MakeString(pattern_data, pattern_len);
    std::string text = MakeString(text_data, text_len);
    absl::string_view text_view = MakeStringView(text_data, text_len);
    
    // Create RE2 object with default options
    re2::RE2::Options options;
    // Set memory limits to avoid excessive memory usage
    options.set_max_mem(64 * 1024 * 1024);  // 64MB limit
    
    re2::RE2 re(pattern, options);
    
    // Test NumberOfCapturingGroups even if regex is invalid
    int num_groups = re.NumberOfCapturingGroups();
    if (num_groups < 0) num_groups = 0;
    
    if (!re.ok()) {
        // If regex is invalid, don't try to use it for matching
        return 0;
    }
    
    // Prepare arguments for capture groups
    std::vector<re2::RE2::Arg> args;
    std::vector<std::string> captured_strings;
    std::vector<const re2::RE2::Arg*> arg_ptrs;
    
    // Limit to at most 4 capture groups for performance
    int max_args = num_groups > 4 ? 4 : num_groups;
    if (max_args < 0) max_args = 0;
    
    for (int i = 0; i < max_args; ++i) {
        captured_strings.emplace_back();
        args.emplace_back(&captured_strings.back());
        arg_ptrs.push_back(&args.back());
    }
    
    // Test ConsumeN
    {
        absl::string_view consume_input = text_view;
        if (!arg_ptrs.empty()) {
            re2::RE2::ConsumeN(&consume_input, re, arg_ptrs.data(), arg_ptrs.size());
        } else {
            // Don't pass any args when n=0
            re2::RE2::ConsumeN(&consume_input, re, nullptr, 0);
        }
    }
    
    // Test PartialMatchN
    {
        if (!arg_ptrs.empty()) {
            re2::RE2::PartialMatchN(text_view, re, arg_ptrs.data(), arg_ptrs.size());
        } else {
            // Don't pass any args when n=0
            re2::RE2::PartialMatchN(text_view, re, nullptr, 0);
        }
    }
    
    // Test Match - be careful with bounds
    {
        std::vector<absl::string_view> submatches;
        int nsubmatch = num_groups + 1; // Include the full match
        if (nsubmatch > 10) nsubmatch = 10; // Limit for performance
        if (nsubmatch < 1) nsubmatch = 1; // At least 1 for the full match
        
        submatches.resize(nsubmatch);
        // Ensure startpos and endpos are within bounds
        size_t startpos = 0;
        size_t endpos = text_view.size();
        if (startpos > endpos) startpos = 0;
        if (endpos > text_view.size()) endpos = text_view.size();
        
        re.Match(text_view, startpos, endpos, re2::RE2::UNANCHORED, 
                submatches.data(), nsubmatch);
    }
    
    // Test FindAndConsume - only if we have args
    {
        if (max_args >= 1) {
            absl::string_view find_input = text_view;
            re2::RE2::FindAndConsume(&find_input, re, &captured_strings[0]);
        }
        if (max_args >= 2) {
            absl::string_view find_input2 = text_view;
            re2::RE2::FindAndConsume(&find_input2, re, &captured_strings[0], &captured_strings[1]);
        }
        if (max_args >= 3) {
            absl::string_view find_input3 = text_view;
            re2::RE2::FindAndConsume(&find_input3, re, &captured_strings[0], 
                                    &captured_strings[1], &captured_strings[2]);
        }
    }
    
    // Test FullMatchN
    {
        if (!arg_ptrs.empty()) {
            re2::RE2::FullMatchN(text_view, re, arg_ptrs.data(), arg_ptrs.size());
        } else {
            // Don't pass any args when n=0
            re2::RE2::FullMatchN(text_view, re, nullptr, 0);
        }
    }
    
    // Test with empty strings
    {
        absl::string_view empty;
        std::vector<absl::string_view> empty_submatches(1);
        re.Match(empty, 0, 0, re2::RE2::UNANCHORED, empty_submatches.data(), 1);
        
        absl::string_view empty_consume;
        re2::RE2::ConsumeN(&empty_consume, re, nullptr, 0);
        re2::RE2::PartialMatchN(empty, re, nullptr, 0);
        re2::RE2::FullMatchN(empty, re, nullptr, 0);
    }
    
    return 0;
}