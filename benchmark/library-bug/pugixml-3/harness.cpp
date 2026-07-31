#include "pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough data for XML content + path + attributes
    if (size < 32) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // Consume fixed-size data first
    uint8_t parse_options = fdp.ConsumeIntegral<uint8_t>();
    char path_delimiter = fdp.ConsumeIntegral<char>();
    char attribute_delimiter = fdp.ConsumeIntegral<char>();
    bool use_string_view = fdp.ConsumeBool();
    
    // Consume variable-size data for XML content
    std::string xml_content = fdp.ConsumeRandomLengthString(2048);
    
    // Consume path strings for navigation testing
    std::vector<std::string> paths;
    for (int i = 0; i < 5 && fdp.remaining_bytes() > 10; i++) {
        paths.push_back(fdp.ConsumeRandomLengthString(256));
    }
    
    // Consume attribute data for find_child_by_attribute testing
    std::vector<std::string> node_names;
    std::vector<std::string> attr_names;
    std::vector<std::string> attr_values;
    
    for (int i = 0; i < 5 && fdp.remaining_bytes() > 30; i++) {
        node_names.push_back(fdp.ConsumeRandomLengthString(64));
        attr_names.push_back(fdp.ConsumeRandomLengthString(64));
        attr_values.push_back(fdp.ConsumeRandomLengthString(128));
    }
    
    // Consume child names for child_value testing
    std::vector<std::string> child_names;
    for (int i = 0; i < 3 && fdp.remaining_bytes() > 10; i++) {
        child_names.push_back(fdp.ConsumeRandomLengthString(64));
    }
    
    // Create XML document
    pugi::xml_document doc;
    pugi::xml_parse_result parse_result;
    
    // Step 1: Parse XML document using load_string as specified in guidance
    parse_result = doc.load_string(xml_content.c_str(), parse_options);
    
    // If parsing failed, create a structured test document
    if (!parse_result) {
        doc.reset();
        
        // Step 2: Get document element (create one if needed)
        pugi::xml_node root = doc.append_child("root");
        
        // Step 3: Create a test structure with nested elements and attributes
        // Create multiple levels for path navigation testing
        pugi::xml_node level1 = root.append_child("level1");
        level1.append_attribute("id") = "1";
        level1.append_attribute("type") = "parent";
        level1.text().set("Level 1 text");
        
        pugi::xml_node level2a = level1.append_child("level2");
        level2a.append_attribute("id") = "2a";
        level2a.append_attribute("category") = "A";
        level2a.text().set("Level 2A text");
        
        pugi::xml_node level2b = level1.append_child("level2");
        level2b.append_attribute("id") = "2b";
        level2b.append_attribute("category") = "B";
        level2b.text().set("Level 2B text");
        
        pugi::xml_node level3a = level2a.append_child("level3");
        level3a.append_attribute("id") = "3a";
        level3a.append_attribute("subtype") = "final";
        level3a.text().set("Level 3A text");
        
        pugi::xml_node level3b = level2a.append_child("level3");
        level3b.append_attribute("id") = "3b";
        level3b.append_attribute("subtype") = "final";
        level3b.text().set("Level 3B text");
        
        // Create nodes with specific attributes for find_child_by_attribute testing
        for (size_t i = 0; i < node_names.size() && i < attr_names.size() && i < attr_values.size(); i++) {
            if (!node_names[i].empty() && !attr_names[i].empty()) {
                pugi::xml_node test_node = root.append_child(node_names[i].c_str());
                test_node.append_attribute(attr_names[i].c_str()) = attr_values[i].c_str();
                
                // Add child nodes with text for child_value testing
                for (const auto& child_name : child_names) {
                    if (!child_name.empty()) {
                        pugi::xml_node child = test_node.append_child(child_name.c_str());
                        child.text().set(("Child text for " + child_name).c_str());
                    }
                }
            }
        }
    }
    
    // Get the document element
    pugi::xml_node root = doc.document_element();
    if (!root) {
        return 0;
    }
    
    // Step 4: Test first_element_by_path with various path strings
    for (const auto& path : paths) {
        if (!path.empty()) {
            // Test with default delimiter
            pugi::xml_node found_by_path = root.first_element_by_path(path.c_str());
            
            // Test with custom delimiter
            if (path_delimiter != '/') {
                pugi::xml_node found_by_custom_delim = root.first_element_by_path(path.c_str(), path_delimiter);
            }
        }
    }
    
    // Step 5: Test find_child_by_attribute (both variants)
    for (size_t i = 0; i < attr_names.size() && i < attr_values.size(); i++) {
        if (!attr_names[i].empty() && !attr_values[i].empty()) {
            // Variant 1: find_child_by_attribute(name, attr_name, attr_value)
            if (i < node_names.size() && !node_names[i].empty()) {
                pugi::xml_node found1 = root.find_child_by_attribute(
                    node_names[i].c_str(), 
                    attr_names[i].c_str(), 
                    attr_values[i].c_str()
                );
            }
            
            // Variant 2: find_child_by_attribute(attr_name, attr_value)
            pugi::xml_node found2 = root.find_child_by_attribute(
                attr_names[i].c_str(), 
                attr_values[i].c_str()
            );
        }
    }
    
    // Step 6: Test path() function on found nodes
    // Test path on root with default delimiter
    std::string root_path = root.path();
    
    // Test path on root with custom delimiter
    std::string root_path_custom = root.path(path_delimiter);
    
    // Traverse some nodes and get their paths
    for (pugi::xml_node child = root.first_child(); child; child = child.next_sibling()) {
        std::string child_path = child.path();
        std::string child_path_custom = child.path(attribute_delimiter);
        
        // Step 7: Test attribute() function (both variants) on child nodes
        for (const auto& attr_name : attr_names) {
            if (!attr_name.empty()) {
                // Variant 1: attribute(const char_t* name, xml_attribute& attr) const
                pugi::xml_attribute attr1;
                bool has_attr1 = child.attribute(attr_name.c_str(), attr1);
                
                // Variant 2: attribute with string_view (if available)
                #ifdef PUGIXML_HAS_STRING_VIEW
                if (use_string_view) {
                    std::string_view sv(attr_name);
                    pugi::xml_attribute attr2;
                    bool has_attr2 = child.attribute(sv, attr2);
                }
                #endif
                
                // Also test the simpler attribute(name) getter
                pugi::xml_attribute simple_attr = child.attribute(attr_name.c_str());
            }
        }
        
        // Step 8: Test child_value() function (both variants)
        // Variant 1: child_value() - get value of the node itself
        const char* node_value = child.child_value();
        
        // Variant 2: child_value(const char_t* name) - get value of named child
        for (const auto& child_name : child_names) {
            if (!child_name.empty()) {
                const char* named_child_value = child.child_value(child_name.c_str());
            }
        }
        
        // Recursively test child nodes
        for (pugi::xml_node grandchild = child.first_child(); grandchild; grandchild = grandchild.next_sibling()) {
            // Test path on grandchild
            std::string grandchild_path = grandchild.path();
            
            // Test first_element_by_path from grandchild
            for (const auto& path : paths) {
                if (!path.empty()) {
                    pugi::xml_node found_from_grandchild = grandchild.first_element_by_path(path.c_str());
                }
            }
        }
    }
    
    // Additional comprehensive testing of path navigation
    // Create a more complex structure for thorough testing
    pugi::xml_node test_root = doc.append_child("test_structure");
    
    // Build a multi-level structure with predictable paths using fuzzer-provided data
    std::string level1_name = fdp.ConsumeRandomLengthString(16);
    std::string level2_name = fdp.ConsumeRandomLengthString(16);
    std::string level3_name = fdp.ConsumeRandomLengthString(16);
    std::string test_attr_name = fdp.ConsumeRandomLengthString(16);
    std::string test_attr_value = fdp.ConsumeRandomLengthString(32);
    
    if (!level1_name.empty() && !level2_name.empty() && !level3_name.empty()) {
        pugi::xml_node a = test_root.append_child(level1_name.c_str());
        pugi::xml_node b = a.append_child(level2_name.c_str());
        pugi::xml_node c = b.append_child(level3_name.c_str());
        
        if (!test_attr_name.empty()) {
            c.append_attribute(test_attr_name.c_str()) = test_attr_value.c_str();
        }
        
        std::string nested_text = fdp.ConsumeRandomLengthString(64);
        c.text().set(nested_text.c_str());
        
        // Test predictable path navigation with fuzzer-provided path
        std::string path_str = level1_name + "/" + level2_name + "/" + level3_name;
        pugi::xml_node found_c = test_root.first_element_by_path(path_str.c_str());
        
        if (found_c) {
            // Test path() on found node
            std::string c_path = found_c.path();
            
            // Test attribute access with fuzzer-provided attribute name
            if (!test_attr_name.empty()) {
                pugi::xml_attribute test_attr;
                bool has_test_attr = found_c.attribute(test_attr_name.c_str(), test_attr);
            }
            
            // Test child_value
            const char* c_value = found_c.child_value();
            
            // Test find_child_by_attribute from parent with fuzzer-provided values
            if (!test_attr_name.empty()) {
                pugi::xml_node found_by_attr = b.find_child_by_attribute(test_attr_name.c_str(), test_attr_value.c_str());
            }
        }
    }
    
    // Test with various delimiters using fuzzer-provided delimiter
    std::string custom_delim_name = fdp.ConsumeRandomLengthString(16);
    std::string delim_child_name = fdp.ConsumeRandomLengthString(32);
    char custom_delim_char = fdp.ConsumeIntegral<char>();
    
    if (!custom_delim_name.empty() && !delim_child_name.empty()) {
        pugi::xml_node custom_delim = test_root.append_child(custom_delim_name.c_str());
        pugi::xml_node delim_child = custom_delim.append_child(delim_child_name.c_str());
        
        std::string delim_text = fdp.ConsumeRandomLengthString(64);
        delim_child.text().set(delim_text.c_str());
        
        // Test path with custom delimiter
        std::string custom_path = delim_child.path(custom_delim_char);
    }
    
    // Step 9: Clean up document
    doc.reset();
    doc.reset();
    
    return 0;
}
