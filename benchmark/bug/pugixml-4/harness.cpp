#include "pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough input for XML parsing, XPath variable operations, and text manipulation
    if (size < 512) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // ==================== STEP 1: Parse XML document ====================
    pugi::xml_document doc;
    
    // Consume parse options from input
    unsigned int parse_options = fdp.ConsumeIntegral<unsigned int>();
    
    // Consume XML data - use bounded amount to leave input for other operations
    size_t max_xml_size = std::min<size_t>(fdp.remaining_bytes(), 4096);
    if (max_xml_size < 300) {
        // Not enough input for meaningful testing
        return 0;
    }
    
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(300, max_xml_size);
    std::vector<uint8_t> xml_data = fdp.ConsumeBytes<uint8_t>(xml_size);
    
    pugi::xml_parse_result result = doc.load_buffer(
        xml_data.data(),
        xml_size,
        parse_options
    );
    
    // If parsing completely fails, create a minimal document for testing
    if (!result) {
        doc.reset();
        pugi::xml_node root = doc.append_child("root");
        // Add some nodes for testing
        for (int i = 0; i < 5 && fdp.remaining_bytes() > 30; i++) {
            std::string node_name = "node_" + std::to_string(i);
            pugi::xml_node child = root.append_child(node_name.c_str());
            if (child) {
                std::string text = "text_" + std::to_string(i);
                child.append_child(pugi::node_pcdata).set_value(text.c_str());
            }
        }
    }
    
    // Get root node to work with
    pugi::xml_node root = doc.document_element();
    if (root.empty()) {
        root = doc.first_child();
        if (root.empty()) {
            root = doc.append_child("root");
        }
    }
    
    // ==================== STEP 2: Create xpath_variable_set instances ====================
    pugi::xpath_variable_set vars1;
    pugi::xpath_variable_set vars2;
    // Add different types of variables
    const char* var_names[] = {"int_var", "double_var", "bool_var", "string_var", "nodeset_var"};
    pugi::xpath_value_type types[] = {
        pugi::xpath_type_number,
        pugi::xpath_type_number,
        pugi::xpath_type_boolean,
        pugi::xpath_type_string,
        pugi::xpath_type_node_set
    };
    
    for (int i = 0; i < 5 && fdp.remaining_bytes() > 10; i++) {
        vars1.add(var_names[i], types[i]);
    }

    
    // ==================== STEP 4: Set variable values using various set() overloads ====================
    // Set boolean variable
    if (fdp.remaining_bytes() > 1) {
        bool bool_val = fdp.ConsumeBool();
        vars1.set("bool_var", bool_val);
    }
    
    // Set double variable
    if (fdp.remaining_bytes() > sizeof(double)) {
        double double_val = fdp.ConsumeFloatingPoint<double>();
        vars1.set("double_var", double_val);
    }
    
    // Set string variable
    if (fdp.remaining_bytes() > 10) {
        std::string string_val = fdp.ConsumeRandomLengthString(50);
        vars1.set("string_var", string_val.c_str());
    }
    
    // Set node_set variable - create a node set from document nodes
    pugi::xpath_node_set node_set;
    if (!root.empty()) {
        // Create xpath_node objects from document nodes
        std::vector<pugi::xpath_node> nodes;
        
        // Add root node
        nodes.push_back(pugi::xpath_node(root));
        
        // Add child nodes
        for (pugi::xml_node child = root.first_child(); child; child = child.next_sibling()) {
            nodes.push_back(pugi::xpath_node(child));
        }
        
        // Create xpath_node_set from the vector
        if (!nodes.empty()) {
            node_set = pugi::xpath_node_set(&nodes[0], &nodes[0] + nodes.size());
        }
        
        vars1.set("nodeset_var", node_set);
    }
    // Test copy assignment operator for xpath_variable_set
    vars2 = vars1;
    
    // ==================== STEP 5: Create xpath_query with variable references ====================
    // Create XPath queries that reference variables
    if (fdp.remaining_bytes() > 20) {
        // Create queries using variable references
        std::string query1 = "//*[@id = $string_var]";
        std::string query2 = "//node()[position() < $int_var]";
        std::string query3 = "//*[$bool_var]";
        
        try {
            pugi::xpath_query xpath1(query1.c_str(), &vars1);
            pugi::xpath_query xpath2(query2.c_str(), &vars2);
            
            // ==================== STEP 6: Evaluate queries using variable set ====================
            if (xpath1) {
                pugi::xpath_node_set result1 = root.select_nodes(xpath1);
                // Also test evaluate
                try {
                    xpath1.evaluate_boolean(root);
                    xpath1.evaluate_number(root);
                    xpath1.evaluate_string(root);
                } catch (...) {
                    // Ignore evaluation errors
                }
            }
            
            if (xpath2) {
                pugi::xpath_node_set result2 = root.select_nodes(xpath2);
            }
        } catch (...) {
            // Ignore XPath compilation errors
        }
    }
    
    // ==================== STEP 7: Test xml_text assignment with various types ====================
    // Get or create a text node
    pugi::xml_node text_node;
    if (!root.empty()) {
        // Find or create a text node
        pugi::xml_node found = root.find_child_by_attribute("node", "type", "text");
        if (found.empty()) {
            text_node = root.append_child("text_node");
            text_node.append_attribute("type") = "text";
        } else {
            text_node = found;
        }
    } else {
        text_node = root.append_child("text_node");
    }
    
    pugi::xml_text text_obj = text_node.text();
    
    if (text_obj) {
        // Test xml_text::operator= with various types
        if (fdp.remaining_bytes() > sizeof(int)) {
            int int_val = fdp.ConsumeIntegral<int>();
            text_obj = int_val;
        }
        
        if (fdp.remaining_bytes() > sizeof(double)) {
            double double_val = fdp.ConsumeFloatingPoint<double>();
            text_obj = double_val;
        }
        
        if (fdp.remaining_bytes() > 1) {
            bool bool_val = fdp.ConsumeBool();
            text_obj = bool_val;
        }
        
        if (fdp.remaining_bytes() > 10) {
            std::string string_val = fdp.ConsumeRandomLengthString(100);
            text_obj = string_val.c_str();
        }
        
        // Test xml_text::set() with various types and precision
        if (fdp.remaining_bytes() > sizeof(double)) {
            double double_val2 = fdp.ConsumeFloatingPoint<double>();
            int precision = fdp.ConsumeIntegralInRange<int>(0, 10);
            text_obj.set(double_val2, precision);
        }
        
        if (fdp.remaining_bytes() > sizeof(float)) {
            float float_val = fdp.ConsumeFloatingPoint<float>();
            int precision = fdp.ConsumeIntegralInRange<int>(0, 10);
            text_obj.set(float_val, precision);
        }
        
        // Test xml_text getters
        text_obj.get();
        text_obj.as_string();
        text_obj.as_int();
        text_obj.as_uint();
        text_obj.as_double();
        text_obj.as_float();
        text_obj.as_bool();
    }
    
    // ==================== STEP 8: Generate node paths using xml_node::path() ====================
    if (!root.empty()) {
        // Get path with default delimiter
        std::string path1 = root.path().c_str();
        
        // Get path with custom delimiter
        if (fdp.remaining_bytes() > 1) {
            char delimiter = fdp.ConsumeIntegral<char>();
            std::string path2 = root.path(delimiter).c_str();
        }
        
        // Get paths for child nodes
        for (pugi::xml_node child = root.first_child(); child && fdp.remaining_bytes() > 0; child = child.next_sibling()) {
            std::string child_path = child.path().c_str();
        }
    }
    
    // ==================== STEP 9: Append buffer content using xml_node::append_buffer() ====================
    if (!root.empty() && fdp.remaining_bytes() > 20) {
        // Consume buffer content
        size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(20, std::min<size_t>(fdp.remaining_bytes(), 1024));
        std::vector<char> buffer = fdp.ConsumeBytes<char>(buffer_size);
        
        // Append buffer as XML fragment
        pugi::xml_parse_result append_result = root.append_buffer(
            buffer.data(),
            buffer.size(),
            pugi::parse_default | pugi::parse_fragment,
            pugi::encoding_auto
        );
        
        // Try with different encodings if we have enough input
        if (fdp.remaining_bytes() > 20) {
            size_t buffer2_size = fdp.ConsumeIntegralInRange<size_t>(20, std::min<size_t>(fdp.remaining_bytes(), 512));
            std::vector<char> buffer2 = fdp.ConsumeBytes<char>(buffer2_size);
            
            pugi::xml_parse_result append_result2 = root.append_buffer(
                buffer2.data(),
                buffer2.size(),
                pugi::parse_default,
                pugi::encoding_utf8
            );
        }
    }
    
    // ==================== STEP 10: Test xpath_variable_set::get() ====================
    // Retrieve variables using get()
    pugi::xpath_variable* var1 = vars1.get("bool_var");
    pugi::xpath_variable* var2 = vars1.get("double_var");
    pugi::xpath_variable* var3 = vars1.get("string_var");
    pugi::xpath_variable* var4 = vars1.get("nodeset_var");
    
    if (var1) var1->get_boolean();
    if (var2) var2->get_number();
    if (var3) var3->get_string();
    if (var4) var4->get_node_set();
    
    // ==================== STEP 11: Clean up ====================
    // The destructors will handle cleanup automatically
    
    return 0;
}
