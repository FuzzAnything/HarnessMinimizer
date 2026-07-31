#include "pugixml.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) {
        return 0;  // Insufficient input for meaningful testing
    }
    // Simple input splitting without FuzzedDataProvider
    // First byte: flags choice
    // Second byte: encoding choice  
    // Remaining bytes: XML data
    
    uint8_t flags_choice = data[0];
    uint8_t encoding_choice = data[1];
    const uint8_t* xml_data = data + 2;
    size_t xml_size = size - 2;
    
    if (xml_size == 0) {
        return 0;  // No XML data to parse
    }
    
    // Select from various parsing flag combinations
    unsigned int parse_flags = pugi::parse_default;
    switch (flags_choice % 8) {
        case 0: parse_flags = pugi::parse_minimal; break;
        case 1: parse_flags = pugi::parse_default; break;
        case 2: parse_flags = pugi::parse_full; break;
        case 3: parse_flags = pugi::parse_default | pugi::parse_fragment; break;
        case 4: parse_flags = pugi::parse_default | pugi::parse_trim_pcdata; break;
        case 5: parse_flags = pugi::parse_default | pugi::parse_ws_pcdata; break;
        case 6: parse_flags = pugi::parse_default | pugi::parse_declaration | pugi::parse_doctype; break;
        case 7: parse_flags = pugi::parse_full | pugi::parse_fragment; break;
    }
    
    // Consume encoding choice
    pugi::xml_encoding encoding = pugi::encoding_auto;
    switch (encoding_choice % 9) {
        case 0: encoding = pugi::encoding_auto; break;
        case 1: encoding = pugi::encoding_utf8; break;
        case 2: encoding = pugi::encoding_utf16_le; break;
        case 3: encoding = pugi::encoding_utf16_be; break;
        case 4: encoding = pugi::encoding_utf16; break;
        case 5: encoding = pugi::encoding_utf32_le; break;
        case 6: encoding = pugi::encoding_utf32_be; break;
        case 7: encoding = pugi::encoding_utf32; break;
        case 8: encoding = pugi::encoding_latin1; break;
    }
    
    // Helper function to check if encoding requires alignment
    auto encoding_requires_alignment = [](pugi::xml_encoding enc) -> std::pair<bool, size_t> {
        switch (enc) {
            case pugi::encoding_utf16_le:
            case pugi::encoding_utf16_be:
            case pugi::encoding_utf16:
                return {true, 2};  // 2-byte alignment required
            case pugi::encoding_utf32_le:
            case pugi::encoding_utf32_be:
            case pugi::encoding_utf32:
                return {true, 4};  // 4-byte alignment required
            default:
                return {false, 1}; // No special alignment required
        }
    };
    
    // Helper function to create aligned buffer if needed
    auto get_aligned_buffer = [&](const uint8_t* input_data, size_t input_size, 
                                  pugi::xml_encoding enc) -> std::pair<std::unique_ptr<uint8_t[]>, const uint8_t*> {
        auto [requires_align, align_size] = encoding_requires_alignment(enc);
        
        if (!requires_align || input_size == 0) {
            return {nullptr, input_data};  // No alignment needed, use original pointer
        }
        
        // Check if input pointer is already properly aligned
        if (reinterpret_cast<uintptr_t>(input_data) % align_size == 0) {
            return {nullptr, input_data};  // Already aligned, use original pointer
        }
        
        // Create aligned buffer
        size_t aligned_size = input_size;
        std::unique_ptr<uint8_t[]> aligned_buffer(new uint8_t[aligned_size]);
        std::memcpy(aligned_buffer.get(), input_data, aligned_size);
        
        return {std::move(aligned_buffer), aligned_buffer.get()};
    };
    
    // Test 1: load_buffer (copies the buffer)
    {
        pugi::xml_document doc1;
        
        // Get aligned buffer if needed for UTF-16/UTF-32 encodings
        auto [aligned_buffer1, buffer1_ptr] = get_aligned_buffer(xml_data, xml_size, encoding);
        
        pugi::xml_parse_result result1 = doc1.load_buffer(
            buffer1_ptr, xml_size, parse_flags, encoding);
        
        // Check parsing result but continue regardless of success/failure
        (void)result1;  // Result intentionally ignored to test both valid and invalid XML
    }
    
    // Test 2: load_string (requires null-terminated string)
    {
        // Create a null-terminated copy of the buffer
        std::string xml_string(reinterpret_cast<const char*>(xml_data), 
                              std::min(xml_size, (size_t)1024));
        
        pugi::xml_document doc2;
        pugi::xml_parse_result result2 = doc2.load_string(xml_string.c_str(), parse_flags);
        (void)result2;
    }
    
    // Test 3: load_buffer_inplace (modifies buffer in place)
    {
        // Create a mutable copy of the buffer for in-place parsing
        // Note: vector allocation might not guarantee proper alignment for UTF-16/UTF-32
        // So we use aligned buffer if needed
        auto [aligned_buffer3, buffer3_ptr] = get_aligned_buffer(xml_data, xml_size, encoding);
        
        // Create mutable copy from aligned buffer
        std::vector<uint8_t> mutable_buffer;
        if (aligned_buffer3) {
            // Use the already aligned buffer as vector
            mutable_buffer.assign(buffer3_ptr, buffer3_ptr + xml_size);
        } else {
            // Create new vector from original data
            mutable_buffer.assign(xml_data, xml_data + xml_size);
        }
        
        pugi::xml_document doc3;
        pugi::xml_parse_result result3 = doc3.load_buffer_inplace(
            mutable_buffer.data(), mutable_buffer.size(), parse_flags, encoding);
        (void)result3;
    }
    
    // Test 4: load_buffer with different flag combinations
    {
        pugi::xml_document doc4;
        
        // Get aligned buffer if needed for UTF-16/UTF-32 encodings
        auto [aligned_buffer4, buffer4_ptr] = get_aligned_buffer(xml_data, xml_size, encoding);
        
        // Test with minimal flags
        pugi::xml_parse_result result4a = doc4.load_buffer(
            buffer4_ptr, xml_size, pugi::parse_minimal, encoding);
        (void)result4a;
        
        // Reset and test with full flags
        doc4.reset();
        pugi::xml_parse_result result4b = doc4.load_buffer(
            buffer4_ptr, xml_size, pugi::parse_full, encoding);
        (void)result4b;
        
        // Reset and test with custom flag combination
        doc4.reset();
        unsigned int custom_flags = pugi::parse_default | 
                                   pugi::parse_comments | 
                                   pugi::parse_pi;
        pugi::xml_parse_result result4c = doc4.load_buffer(
            buffer4_ptr, xml_size, custom_flags, encoding);
        (void)result4c;
    }
    
    // Test 5: Try to parse as fragment if we have enough data
    if (xml_size > 16) {
        pugi::xml_document doc5;
        
        // Get aligned buffer if needed for UTF-16/UTF-32 encodings
        auto [aligned_buffer5, buffer5_ptr] = get_aligned_buffer(xml_data, xml_size, encoding);
        
        pugi::xml_parse_result result5 = doc5.load_buffer(
            buffer5_ptr, xml_size, 
            parse_flags | pugi::parse_fragment, encoding);
        (void)result5;
    }
    
    // Test 6: Test memory ownership variant if we have enough data
    // FIX: Use malloc() instead of new[] for pugixml's load_buffer_inplace_own
    if (xml_size > 32) {
        // Create a copy for ownership variant
        std::vector<uint8_t> owned_buffer(xml_data, xml_data + xml_size);
        
        // Check if we need alignment for UTF-16/UTF-32
        auto [requires_align, align_size] = encoding_requires_alignment(encoding);
        if (requires_align) {
            // Ensure the allocated memory is properly aligned
            // posix_memalign requires alignment to be at least sizeof(void*) and a power of two
            size_t actual_align = std::max(align_size, sizeof(void*));
            void* aligned_mem = nullptr;
            if (posix_memalign(&aligned_mem, actual_align, owned_buffer.size()) != 0) {
                return 0;  // Allocation failed
            }
            
            uint8_t* owned_data = static_cast<uint8_t*>(aligned_mem);
            std::memcpy(owned_data, owned_buffer.data(), owned_buffer.size());
            
            pugi::xml_document doc6;
            pugi::xml_parse_result result6 = doc6.load_buffer_inplace_own(
                owned_data, owned_buffer.size(), parse_flags, encoding);
            (void)result6;
            
            // Note: The buffer will be freed by pugixml using free() when doc6 is destroyed
        } else {
            // Allocate using malloc() as required by pugixml's load_buffer_inplace_own
            uint8_t* owned_data = static_cast<uint8_t*>(malloc(owned_buffer.size()));
            if (owned_data == nullptr) {
                return 0;  // Allocation failed
            }
            std::memcpy(owned_data, owned_buffer.data(), owned_buffer.size());
            
            pugi::xml_document doc6;
            pugi::xml_parse_result result6 = doc6.load_buffer_inplace_own(
                owned_data, owned_buffer.size(), parse_flags, encoding);
            (void)result6;
            
            // Note: The buffer will be freed by pugixml using free() when doc6 is destroyed
        }
    }
    
    return 0;
}
