/**
 * pugixml fuzzing harness - Comprehensive XML parsing and manipulation
 * Targets: XML parsing, node traversal, attribute access, document manipulation
 * 
 * This harness combines functionality from existing fuzzing tests and adds
 * additional API coverage for comprehensive testing.
 */

#include "pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>

#include <stdint.h>
#include <string>
#include <vector>
#include <sstream>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;  // Minimum size for meaningful testing
    
    FuzzedDataProvider fdp(data, size);
    
    // Create XML document
    pugi::xml_document doc;
    
    // Try different parsing options with the input data
    const unsigned int parse_options[] = {
        pugi::parse_default,
        pugi::parse_minimal,
        pugi::parse_full,
        pugi::parse_ws_pcdata | pugi::parse_eol,
        pugi::parse_ws_pcdata_single | pugi::parse_eol,
        pugi::parse_declaration,
        pugi::parse_pi,
        pugi::parse_comments,
        pugi::parse_cdata,
        pugi::parse_escapes,
        pugi::parse_wconv_attribute,
        pugi::parse_wnorm_attribute,
        pugi::parse_trim_pcdata,
        pugi::parse_fragment,
        pugi::parse_embed_pcdata,
        pugi::parse_merge_pcdata
    };
    
    // Try parsing with different options
    for (unsigned int i = 0; i < 3 && fdp.remaining_bytes() > 10; ++i) {
        unsigned int options = parse_options[fdp.ConsumeIntegralInRange<size_t>(0, sizeof(parse_options)/sizeof(parse_options[0]) - 1)];
        std::string xml_data = fdp.ConsumeRandomLengthString(1024);
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, xml_data.length());
        pugi::xml_parse_result result = doc.load_buffer(xml_data.c_str(), buffer_size, options);
        // If parsing succeeded, explore the document structure
        if (result) {
            // Get document element
            pugi::xml_node root = doc.document_element();
            
            if (!root.empty()) {
                // Traverse children
                for (pugi::xml_node child = root.first_child(); child; child = child.next_sibling()) {
                    // Get node type
                    pugi::xml_node_type type = child.type();
                    
                    // Get node name and value
                    const char* name = child.name();
                    const char* value = child.value();
                    
                    // Get child value
                    const char* child_value = child.child_value();
                    
                    // Get text object
                    pugi::xml_text text = child.text();
                    if (text) {
                        std::string text_str = text.get();
                    }
                    
                    // Traverse attributes
                    for (pugi::xml_attribute attr = child.first_attribute(); attr; attr = attr.next_attribute()) {
                        const char* attr_name = attr.name();
                        const char* attr_value = attr.value();
                        std::string attr_value_str = attr.as_string();
                        
                        // Try different attribute value types
                        int attr_int = attr.as_int();
                        unsigned int attr_uint = attr.as_uint();
                        double attr_double = attr.as_double();
                        float attr_float = attr.as_float();
                        bool attr_bool = attr.as_bool();
                    }
                    
                    // Find specific child by name
                    std::string search_name = fdp.ConsumeRandomLengthString(20);
                    pugi::xml_node found_child = child.child(search_name.c_str());
                    
                    // Find specific attribute by name
                    std::string search_attr = fdp.ConsumeRandomLengthString(20);
                    pugi::xml_attribute found_attr = child.attribute(search_attr.c_str());
                }
                
                // Try to find nodes using various methods
                std::string find_name = fdp.ConsumeRandomLengthString(20);
                std::string attr_name = fdp.ConsumeRandomLengthString(20);
                std::string attr_value = fdp.ConsumeRandomLengthString(20);
                pugi::xml_node found_node = root.find_child_by_attribute(find_name.c_str(), attr_name.c_str(), attr_value.c_str());
                found_node = root.find_child_by_attribute(attr_name.c_str(), attr_value.c_str());
                // Try document manipulation if we have enough input
                if (fdp.remaining_bytes() > 100) {
                    // Create new nodes
                    std::string new_node_name = fdp.ConsumeRandomLengthString(20);
                    pugi::xml_node new_node = root.append_child(new_node_name.c_str());
                    
                    // Add attributes to new node
                    std::string new_attr_name = fdp.ConsumeRandomLengthString(20);
                    std::string new_attr_value = fdp.ConsumeRandomLengthString(50);
                    pugi::xml_attribute new_attr = new_node.append_attribute(new_attr_name.c_str());
                    new_attr.set_value(new_attr_value.c_str());
                    
                    // Add text content
                    std::string node_text = fdp.ConsumeRandomLengthString(100);
                    new_node.text().set(node_text.c_str());
                    
                    // Try to remove nodes
                    if (!root.first_child().empty()) {
                        root.remove_child(root.first_child());
                    }
                    
                    // Try to remove attributes
                    if (!new_node.first_attribute().empty()) {
                        new_node.remove_attribute(new_node.first_attribute());
                    }
                }
            }
            
            // Reset document for next iteration
            doc.reset();
        }
    }
    
    // Try in-place parsing with remaining data
    if (fdp.remaining_bytes() > 10) {
        std::vector<uint8_t> buffer = fdp.ConsumeRemainingBytes<uint8_t>();
        if (!buffer.empty()) {
            pugi::xml_document doc2;
            pugi::xml_parse_result result = doc2.load_buffer_inplace(buffer.data(), buffer.size());
            // If successful, try printing methods
            if (result) {
                // Try to print to stringstream with different formats
                std::stringstream ss;
                doc2.print(ss);
                
                // Try different formatting options
                const unsigned int format_options[] = {
                    pugi::format_default,
                    pugi::format_indent,
                    pugi::format_raw,
                    pugi::format_no_declaration,
                    pugi::format_no_escapes,
                    pugi::format_save_file_text
                };
                
                if (fdp.remaining_bytes() > 0) {
                    unsigned int format = format_options[fdp.ConsumeIntegralInRange<size_t>(0, sizeof(format_options)/sizeof(format_options[0]) - 1)];
                    std::stringstream ss2;
                    doc2.print(ss2, "\t", format);
                }
            }
        }
    }
    
    return 0;
}
