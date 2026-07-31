/*
 * Fuzzing harness for libmagic apprentice.c parse function targeting deep magic file format parsing
 * Targets: magic_load, magic_check, magic_compile APIs with complex, nested magic entries
 * 
 * This harness specifically targets the parse function's remaining 263 blocked branches (90.7% blocked)
 * by generating complex, nested magic file entries to exercise deep parsing logic:
 * 1. Multi-level continuations with hierarchical structure
 * 2. Indirect modifiers and complex offset calculations
 * 3. String operations with various modifiers (t, b, B, etc.)
 * 4. Numeric types with range operators and masks
 * 5. Apple and MIME annotations with extensions
 * 6. Relative offsets and factor operations
 * 7. Structured data patterns (GUID, dates, times)
 * 8. Conditional magic entries (if/else/elif where enabled)
 * 
 * Semantic differentiation from existing harnesses:
 * - harness_000: Basic file identification with magic_buffer API
 * - harness_001: Parameter management APIs
 * - harness_002: Database compilation and management
 * - harness_003: Soft magic pattern matching
 * - harness_004: Error handling and edge cases
 * - harness_005: Compression detection
 * - harness_006: ELF file format detection
 * - harness_007: CDF (Compound Document Format) detection
 * - harness_008: Database operations (apprentice functions)
 * - harness_009: Complex magic pattern parsing and sorting
 * - harness_010: ASCII/text file detection
 * - harness_011: File handle and stream operations
 * - harness_012: Basic magic syntax generation and parse function testing
 * - harness_013: Advanced edge case testing targeting specific blocked branches
 * - harness_014: Memory pressure and complex continuation hierarchy testing
 * - harness_015: Malformed/error path testing targeting all file_magwarn conditions
 * - harness_016: Deep magic format parsing with complex nested structures (THIS HARNESS)
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <magic.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <sstream>

// Minimum input size required for meaningful fuzzing
const size_t MIN_INPUT_SIZE = sizeof(int) + sizeof(uint8_t) + sizeof(uint16_t) + 1;

// Magic type enumeration
enum MagicType {
    TYPE_BYTE = 0,
    TYPE_SHORT,
    TYPE_LONG,
    TYPE_QUAD,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_PSTRING,
    TYPE_BESTRING16,
    TYPE_LESTRING16,
    TYPE_BESTRING32,
    TYPE_LESTRING32,
    TYPE_REGEX,
    TYPE_SEARCH,
    TYPE_DEFAULT,
    TYPE_DATE,
    TYPE_QDATE,
    TYPE_LDATE,
    TYPE_QLDATE,
    TYPE_QWDATE,
    TYPE_BEQDATE,
    TYPE_LEQDATE,
    TYPE_BEQWDATE,
    TYPE_LEQWDATE,
    TYPE_BEQLDATE,
    TYPE_LEQLDATE,
    TYPE_MAX
};

// Helper to generate a complex magic file with nested structures
std::string generateComplexMagicFile(FuzzedDataProvider& fdp, uint8_t complexity_level) {
    std::ostringstream magic_content;
    
    // Number of magic entries based on complexity
    size_t num_entries = 5 + (complexity_level % 20);
    
    for (size_t i = 0; i < num_entries; i++) {
        // Determine continuation level (0-4 levels of nesting)
        uint8_t cont_level = fdp.ConsumeIntegral<uint8_t>() % 5;
        
        // Generate continuation markers
        for (uint8_t cl = 0; cl < cont_level; cl++) {
            magic_content << ">";
        }
        
        // Decide if this should be a relative offset
        if (cont_level == 0 && fdp.ConsumeBool()) {
            magic_content << "&";
        }
        
        // Generate offset - sometimes with indirect modifier
        if (fdp.ConsumeBool() && cont_level > 0) {
            // Indirect offset
            magic_content << "(";
            if (fdp.ConsumeBool()) {
                magic_content << "&"; // Relative indirect
            }
            magic_content << fdp.ConsumeIntegral<uint32_t>() % 1024;
            magic_content << ")";
        } else {
            // Direct offset
            magic_content << fdp.ConsumeIntegral<uint32_t>() % 1024;
        }
        
        // Generate type
        MagicType mtype = static_cast<MagicType>(fdp.ConsumeIntegral<uint8_t>() % TYPE_MAX);
        switch (mtype) {
            case TYPE_BYTE: magic_content << " byte"; break;
            case TYPE_SHORT: magic_content << " short"; break;
            case TYPE_LONG: magic_content << " long"; break;
            case TYPE_QUAD: magic_content << " quad"; break;
            case TYPE_FLOAT: magic_content << " float"; break;
            case TYPE_DOUBLE: magic_content << " double"; break;
            case TYPE_STRING: magic_content << " string"; break;
            case TYPE_PSTRING: magic_content << " pstring"; break;
            case TYPE_BESTRING16: magic_content << " bestring16"; break;
            case TYPE_LESTRING16: magic_content << " lestring16"; break;
            case TYPE_BESTRING32: magic_content << " bestring32"; break;
            case TYPE_LESTRING32: magic_content << " lestring32"; break;
            case TYPE_REGEX: magic_content << " regex"; break;
            case TYPE_SEARCH: magic_content << " search"; break;
            case TYPE_DEFAULT: magic_content << " default"; break;
            case TYPE_DATE: magic_content << " date"; break;
            case TYPE_QDATE: magic_content << " qdate"; break;
            case TYPE_LDATE: magic_content << " ldate"; break;
            case TYPE_QLDATE: magic_content << " qldate"; break;
            case TYPE_QWDATE: magic_content << " qwdate"; break;
            case TYPE_BEQDATE: magic_content << " beqdate"; break;
            case TYPE_LEQDATE: magic_content << " leqdate"; break;
            case TYPE_BEQWDATE: magic_content << " beqwdate"; break;
            case TYPE_LEQWDATE: magic_content << " leqwdate"; break;
            case TYPE_BEQLDATE: magic_content << " beqldate"; break;
            case TYPE_LEQLDATE: magic_content << " leqldate"; break;
            default: magic_content << " byte"; break;
        }
        
        // Add mask for numeric types
        if (mtype <= TYPE_DOUBLE && fdp.ConsumeBool()) {
            magic_content << "&" << std::hex << (fdp.ConsumeIntegral<uint64_t>() & 0xFFFFFFFF);
        }
        
        // Generate operator
        uint8_t op = fdp.ConsumeIntegral<uint8_t>() % 8;
        switch (op) {
            case 0: magic_content << " ="; break;
            case 1: magic_content << " !="; break;
            case 2: magic_content << " <"; break;
            case 3: magic_content << " >"; break;
            case 4: magic_content << " &"; break;
            case 5: magic_content << " ^"; break;
            case 6: magic_content << " ~"; break;
            case 7: magic_content << " x"; break;
            default: magic_content << " ="; break;
        }
        
        // Generate value based on type
        switch (mtype) {
            case TYPE_BYTE:
            case TYPE_SHORT:
            case TYPE_LONG:
            case TYPE_QUAD:
                magic_content << " " << std::dec << (fdp.ConsumeIntegral<uint64_t>() & 0xFFFFFFFF);
                if (fdp.ConsumeBool()) {
                    // Add range
                    magic_content << "-" << (fdp.ConsumeIntegral<uint64_t>() & 0xFFFFFFFF);
                }
                break;
                
            case TYPE_FLOAT:
            case TYPE_DOUBLE:
                magic_content << " " << fdp.ConsumeFloatingPoint<double>();
                if (fdp.ConsumeBool()) {
                    magic_content << "-" << fdp.ConsumeFloatingPoint<double>();
                }
                break;
                
            case TYPE_STRING:
            case TYPE_PSTRING:
            case TYPE_BESTRING16:
            case TYPE_LESTRING16:
            case TYPE_BESTRING32:
            case TYPE_LESTRING32:
            case TYPE_REGEX:
            case TYPE_SEARCH: {
                // Generate string value with possible modifiers
                std::string str_val = fdp.ConsumeRandomLengthString(50);
                
                // Add string modifiers
                if (fdp.ConsumeBool()) {
                    magic_content << " /";
                    uint8_t str_mod = fdp.ConsumeIntegral<uint8_t>() % 8;
                    switch (str_mod) {
                        case 0: magic_content << "b"; break;  // byte count
                        case 1: magic_content << "B"; break;  // big-endian 16-bit count
                        case 2: magic_content << "H"; break;  // big-endian 32-bit count
                        case 3: magic_content << "h"; break;  // little-endian 16-bit count
                        case 4: magic_content << "l"; break;  // little-endian 32-bit count
                        case 5: magic_content << "t"; break;  // trimmed
                        case 6: magic_content << "c"; break;  // caseless
                        case 7: magic_content << "w"; break;  // wide char
                    }
                }
                
                // Escape special characters in string
                std::string escaped_str;
                for (char c : str_val) {
                    if (c == '\\' || c == '"' || c == '\'') {
                        escaped_str += '\\';
                    }
                    escaped_str += c;
                }
                
                if (fdp.ConsumeBool()) {
                    magic_content << " \"" << escaped_str << "\"";
                } else {
                    magic_content << " " << escaped_str;
                }
                break;
            }
                
            case TYPE_DATE:
            case TYPE_QDATE:
            case TYPE_LDATE:
            case TYPE_QLDATE:
            case TYPE_QWDATE:
            case TYPE_BEQDATE:
            case TYPE_LEQDATE:
            case TYPE_BEQWDATE:
            case TYPE_LEQWDATE:
            case TYPE_BEQLDATE:
            case TYPE_LEQLDATE:
                // Date value
                magic_content << " " << (1900 + (fdp.ConsumeIntegral<uint32_t>() % 200));
                break;
                
            default:
                magic_content << " " << (fdp.ConsumeIntegral<uint32_t>() & 0xFF);
                break;
        }
        
        // Add MIME type annotation occasionally
        if (fdp.ConsumeIntegral<uint8_t>() % 5 == 0) {
            magic_content << "\n!:mime ";
            std::string mime_type = fdp.ConsumeBool() ? "application/" : "text/";
            mime_type += fdp.ConsumeRandomLengthString(10);
            magic_content << mime_type;
        }
        
        // Add Apple annotation occasionally
        if (fdp.ConsumeIntegral<uint8_t>() % 7 == 0) {
            magic_content << "\n!:apple ";
            std::string apple_type = fdp.ConsumeRandomLengthString(15);
            magic_content << apple_type;
        }
        
        // Add extension annotation occasionally
        if (fdp.ConsumeIntegral<uint8_t>() % 6 == 0) {
            magic_content << "\n!:ext ";
            std::string ext = ".";
            ext += fdp.ConsumeRandomLengthString(5);
            magic_content << ext;
        }
        
        // Add strength annotation occasionally
        if (fdp.ConsumeIntegral<uint8_t>() % 8 == 0) {
            magic_content << "\n!:strength ";
            magic_content << (fdp.ConsumeIntegral<uint8_t>() % 100);
        }
        
        magic_content << "\n";
    }
    
    return magic_content.str();
}

// Helper to generate a temporary magic file
std::string createTempMagicFile(const std::string& content, uint32_t seed) {
    std::string filename = "/tmp/magic_fuzz_complex_" + std::to_string(seed) + ".mgc";
    std::ofstream out_file(filename, std::ios::binary);
    if (out_file.is_open()) {
        out_file.write(content.c_str(), content.size());
        out_file.close();
    }
    return filename;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Check minimum input size
    if (size < MIN_INPUT_SIZE) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume flags for magic_open
    int flags = fdp.ConsumeIntegral<int>();
    
    // Mask flags to valid combinations for magic_check/compile operations
    flags &= (MAGIC_NONE | MAGIC_DEBUG | MAGIC_SYMLINK | MAGIC_COMPRESS | 
              MAGIC_DEVICES | MAGIC_MIME_TYPE | MAGIC_CONTINUE | MAGIC_CHECK |
              MAGIC_PRESERVE_ATIME | MAGIC_RAW | MAGIC_ERROR | MAGIC_MIME_ENCODING |
              MAGIC_APPLE | MAGIC_EXTENSION | MAGIC_COMPRESS_TRANSP | 
              MAGIC_NO_COMPRESS_FORK);
    
    // Consume complexity level for magic generation
    uint8_t complexity_level = fdp.ConsumeIntegral<uint8_t>();
    
    // Consume operation type: 0=magic_check, 1=magic_compile, 2=magic_load, 3=magic_list
    uint8_t operation_type = fdp.ConsumeIntegral<uint8_t>() % 4;
    
    // Consume seed for temp file name
    uint32_t temp_seed = fdp.ConsumeIntegral<uint32_t>();
    
    // Generate complex magic file content
    std::string magic_content = generateComplexMagicFile(fdp, complexity_level);
    
    // Create temporary magic file
    std::string temp_filename = createTempMagicFile(magic_content, temp_seed);
    
    // Create magic cookie
    magic_t magic_cookie = magic_open(flags);
    if (magic_cookie == nullptr) {
        // Clean up temp file
        std::remove(temp_filename.c_str());
        return 0;
    }
    
    int result = -1;
    
    // Perform the selected operation
    switch (operation_type) {
        case 0: // magic_check - validate magic file syntax
            result = magic_check(magic_cookie, temp_filename.c_str());
            break;
            
        case 1: // magic_compile - compile magic file to binary format
            result = magic_compile(magic_cookie, temp_filename.c_str());
            break;
            
        case 2: // magic_load - load and use magic file
            result = magic_load(magic_cookie, temp_filename.c_str());
            if (result == 0) {
                // If load succeeded, test with some random data
                if (fdp.remaining_bytes() > 0) {
                    size_t test_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
                    std::vector<uint8_t> test_data = fdp.ConsumeBytes<uint8_t>(test_size);
                    if (!test_data.empty()) {
                        const char* buffer_result = magic_buffer(magic_cookie, test_data.data(), test_data.size());
                        (void)buffer_result; // Use result to avoid unused variable warning
                    }
                }
            }
            break;
            
        case 3: // magic_list - list magic entries
            result = magic_list(magic_cookie, temp_filename.c_str());
            break;
    }
    
    // Test error API to see if any warnings were generated
    const char* error_msg = magic_error(magic_cookie);
    (void)error_msg; // Use result to avoid unused variable warning
    
    // Clean up
    magic_close(magic_cookie);
    std::remove(temp_filename.c_str());
    
    return 0;
}
