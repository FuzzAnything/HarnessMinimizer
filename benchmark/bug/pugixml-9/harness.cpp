// This fuzz driver is generated for library pugixml, aiming to fuzz the following functions:
// pugi::xml_node::append_child at pugixml.cpp:6253:34 in pugixml.hpp
// pugi::xml_node::append_child at pugixml.cpp:6253:34 in pugixml.hpp
// pugi::xml_node::append_child at pugixml.cpp:6253:34 in pugixml.hpp
// pugi::xml_node::insert_child_before at pugixml.cpp:6287:34 in pugixml.hpp
// pugi::xml_node::first_child at pugixml.cpp:5964:34 in pugixml.hpp
// pugi::xml_node::append_attribute at pugixml.cpp:6041:39 in pugixml.hpp
// pugi::xml_node::insert_child_before at pugixml.cpp:6287:34 in pugixml.hpp
// pugi::xml_node::empty at pugixml.cpp:5683:30 in pugixml.hpp
// pugi::xml_node::first_child at pugixml.cpp:5964:34 in pugixml.hpp
// pugi::xml_node::empty at pugixml.cpp:5683:30 in pugixml.hpp
// pugi::xml_node::set_value at pugixml.cpp:6009:30 in pugixml.hpp
// pugi::xml_document::save at pugixml.cpp:7770:34 in pugixml.hpp
// pugi::xml_document::save at pugixml.cpp:7770:34 in pugixml.hpp
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "pugixml.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <sstream>
#include <fstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Initialize pugixml document and nodes
    pugi::xml_document doc;
    
    // Create a root node
    pugi::xml_node root = doc.append_child(pugi::node_element);
    
    // Create some initial nodes to work with
    pugi::xml_node child1 = root.append_child(pugi::node_element);
    pugi::xml_node child2 = root.append_child(pugi::node_element);
    
    // First call: insert_child_before
    // Use Data[0] to determine node type (mod 9 for valid range)
    pugi::xml_node_type type1 = static_cast<pugi::xml_node_type>(Data[0] % 9);
    pugi::xml_node inserted1 = root.insert_child_before(type1, child2);
    
    // Second call: first_child
    pugi::xml_node first = root.first_child();
    
    // Third call: append_attribute
    // Create attribute name from fuzzer data
    std::string attr_name1;
    if (Size > 1) {
        size_t name_len = std::min(Size - 1, static_cast<size_t>(Data[1] % 100));
        attr_name1 = std::string(reinterpret_cast<const char*>(Data + 1), name_len);
    } else {
        attr_name1 = "attr";
    }
    
    // Ensure null termination for append_attribute
    std::string null_term_attr1(attr_name1.data(), attr_name1.length());
    pugi::xml_attribute attr1 = first.append_attribute(null_term_attr1.c_str());
    
    // Fourth call: insert_child_before again
    pugi::xml_node_type type2 = static_cast<pugi::xml_node_type>((Data[0] + 1) % 9);
    pugi::xml_node inserted2 = root.insert_child_before(type2, inserted1.empty() ? child2 : inserted1);
    
    // Fifth call: first_child again
    pugi::xml_node first2 = root.first_child();
    
    // Sixth call: set_value
    // Create value from fuzzer data
    std::string value_str;
    if (Size > 2) {
        size_t value_len = std::min(Size - 2, static_cast<size_t>(Data[2] % 100));
        value_str = std::string(reinterpret_cast<const char*>(Data + 2), value_len);
    } else {
        value_str = "value";
    }
    
    // Ensure null termination for set_value
    std::string null_term_value(value_str.data(), value_str.length());
    if (!first2.empty()) {
        first2.set_value(null_term_value.c_str());
    }
    
    // Seventh call: save
    // Save to a string stream
    std::stringstream ss;
    pugi::xml_writer_stream writer(ss);
    try {
        doc.save(writer, "\t", pugi::format_default, pugi::encoding_auto);
    } catch (...) {
        // Ignore exceptions during save
    }
    
    // Also try saving to a file
    std::ofstream file("./dummy_file");
    if (file) {
        pugi::xml_writer_file file_writer(static_cast<void*>(file.rdbuf()));
        try {
            doc.save(file_writer, "\t", pugi::format_default, pugi::encoding_auto);
        } catch (...) {
            // Ignore exceptions
        }
        file.close();
    }
    
    return 0;
}