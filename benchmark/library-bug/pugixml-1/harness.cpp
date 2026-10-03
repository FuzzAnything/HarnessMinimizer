#include "pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need XML content + save options
    if (size < 32) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Split input: first part for XML content
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(16, size / 2);
    std::vector<uint8_t> xml_data = fdp.ConsumeBytes<uint8_t>(xml_size);
    
    // Parse XML document
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_buffer(
        xml_data.data(),
        xml_data.size(),
        pugi::parse_default
    );
    
    // If parsing failed, create a fallback document from remaining input
    if (!result) {
        // Use remaining input for fallback XML
        std::vector<uint8_t> remaining = fdp.ConsumeRemainingBytes<uint8_t>();
        if (remaining.empty()) {
            // If no input left, create minimal XML
            const char* minimal_xml = "<root/>";
            doc.load_buffer(minimal_xml, strlen(minimal_xml));
        } else {
            doc.load_buffer(remaining.data(), remaining.size(), pugi::parse_default);
        }
    }
    
    // Optional: manipulate document to create more diverse output
    // This helps exercise different serialization paths
    pugi::xml_node root = doc.document_element();
    if (root.empty()) {
        // Create a root node if none exists
        root = doc.append_child(pugi::node_element);
        std::string root_name = fdp.ConsumeRandomLengthString(15);
        root.set_name(root_name.empty() ? "fuzzed_root" : root_name.c_str());
    }
    
    // Add some random attributes and child nodes based on fuzzer input
    // This creates more complex XML structures for serialization testing
    unsigned int manipulation_op = fdp.ConsumeIntegralInRange<unsigned int>(0, 5);
    switch (manipulation_op) {
        case 0:
            // Add attribute
            {
                std::string attr_name = fdp.ConsumeRandomLengthString(10);
                std::string attr_value = fdp.ConsumeRandomLengthString(20);
                root.append_attribute(attr_name.empty() ? "fuzzed_attr" : attr_name.c_str())
                    .set_value(attr_value.c_str());
            }
            break;
        case 1:
            // Add child element
            {
                std::string child_name = fdp.ConsumeRandomLengthString(15);
                std::string child_text = fdp.ConsumeRandomLengthString(30);
                pugi::xml_node child = root.append_child(pugi::node_element);
                child.set_name(child_name.empty() ? "child" : child_name.c_str());
                child.append_child(pugi::node_pcdata).set_value(child_text.c_str());
            }
            break;
        case 2:
            // Add multiple children
            for (int i = 0; i < 3 && fdp.remaining_bytes() > 0; i++) {
                std::string child_name = "child_" + std::to_string(i);
                if (fdp.remaining_bytes() > 0) {
                    std::string random_name = fdp.ConsumeRandomLengthString(10);
                    if (!random_name.empty()) {
                        child_name = random_name;
                    }
                }
                pugi::xml_node child = root.append_child(pugi::node_element);
                child.set_name(child_name.c_str());
            }
            break;
        case 3:
            // Add CDATA section
            {
                std::string cdata_value = fdp.ConsumeRandomLengthString(40);
                root.append_child(pugi::node_cdata).set_value(cdata_value.c_str());
            }
            break;
        case 4:
            // Add comment
            {
                std::string comment_text = fdp.ConsumeRandomLengthString(25);
                root.append_child(pugi::node_comment).set_value(comment_text.c_str());
            }
            break;
        case 5:
            // Add processing instruction
            {
                std::string pi_name = fdp.ConsumeRandomLengthString(10);
                std::string pi_value = fdp.ConsumeRandomLengthString(20);
                pugi::xml_node pi_node = root.append_child(pugi::node_pi);
                if (pi_node) {
                    pi_node.set_name(pi_name.empty() ? "fuzzed_pi" : pi_name.c_str());
                    pi_node.set_value(pi_value.c_str());
                }
            }
            break;
    }
    
    // Consume save options from remaining input
    pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(
        fdp.ConsumeIntegralInRange<int>(0, 8)  // encoding_auto (0) to encoding_latin1 (8)
    );
    unsigned int flags = fdp.ConsumeIntegral<unsigned int>();
    
    // Consume indent string
    std::string indent_str = fdp.ConsumeRandomLengthString(10);
    const char* indent = indent_str.empty() ? "\t" : indent_str.c_str();
    
    // Test 1: save_file with char* path
    std::string temp_filename = "/tmp/fuzzed_xml_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
    bool save_result = doc.save_file(temp_filename.c_str(), indent, flags, encoding);
    (void)save_result; // Use result to avoid unused variable warning
    
    // Test 2: save_file with wchar_t* path (if supported)
    #ifdef _WIN32
    std::wstring wtemp_filename = L"/tmp/fuzzed_xml_" + std::to_wstring(fdp.ConsumeIntegral<uint32_t>()) + L".xml";
    bool save_result_w = doc.save_file(wtemp_filename.c_str(), indent, flags, encoding);
    (void)save_result_w;
    #endif
    
    // Test 3: save with xml_writer_file
    // Create a temporary file for writing
    std::string temp_file2 = "/tmp/fuzzed_xml_writer_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
    FILE* temp_file = fopen(temp_file2.c_str(), "wb");
    if (temp_file) {
        pugi::xml_writer_file writer(temp_file);
        doc.save(writer, indent, flags, encoding);
        fclose(temp_file);
    }
    
    // Test 4: save with xml_writer_stream (requires STL)
    #ifndef PUGIXML_NO_STL
    {
        std::stringstream stream;
        pugi::xml_writer_stream stream_writer(stream);
        doc.save(stream_writer, indent, flags, encoding);
        
        // Also test with wide stream if available
        std::wstringstream wstream;
        pugi::xml_writer_stream wstream_writer(wstream);
        doc.save(wstream_writer, indent, flags);
    }
    #endif
    
    // Test 5: save with std::ostream (requires STL)
    #ifndef PUGIXML_NO_STL
    {
        std::stringstream ostream;
        doc.save(ostream, indent, flags, encoding);
        
        // Also test with wide ostream
        std::wstringstream wostream;
        doc.save(wostream, indent, flags);
    }
    #endif
    
    // Test different encoding combinations
    // Try a few more encoding options with different flags
    unsigned int alt_flags = fdp.ConsumeIntegral<unsigned int>();
    pugi::xml_encoding alt_encoding = static_cast<pugi::xml_encoding>(
        fdp.ConsumeIntegralInRange<int>(0, 5)
    );
    
    // Test with different indent
    std::string alt_indent = fdp.ConsumeRandomLengthString(5);
    if (!alt_indent.empty()) {
        std::string temp_file3 = "/tmp/fuzzed_xml_alt_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
        doc.save_file(temp_file3.c_str(), alt_indent.c_str(), alt_flags, alt_encoding);
    }
    
    // Test save with no indent (empty string)
    if (fdp.ConsumeBool()) {
        std::string temp_file4 = "/tmp/fuzzed_xml_noindent_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
        doc.save_file(temp_file4.c_str(), "", alt_flags, alt_encoding);
    }
    
    // Test save with default parameters
    if (fdp.ConsumeBool()) {
        std::string temp_file5 = "/tmp/fuzzed_xml_default_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".xml";
        doc.save_file(temp_file5.c_str());
    }
    
    // Cleanup: reset document
    doc.reset();
    
    // Clean up temporary files if they exist
    remove(temp_filename.c_str());
    #ifdef _WIN32
    _wremove(wtemp_filename.c_str());
    #endif
    remove(temp_file2.c_str());
    
    return 0;
}
