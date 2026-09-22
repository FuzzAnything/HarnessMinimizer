// This fuzz driver is generated for library pugixml, aiming to fuzz the following functions:
// pugi::xml_attribute::as_string at pugixml.cpp:5302:44 in pugixml.hpp
// pugi::xml_attribute::as_string at pugixml.cpp:5302:44 in pugixml.hpp
// pugi::xml_attribute::name at pugixml.cpp:5365:44 in pugixml.hpp
// pugi::xml_attribute::value at pugixml.cpp:5372:44 in pugixml.hpp
// pugi::xml_attribute::set_name at pugixml.cpp:5459:35 in pugixml.hpp
// pugi::xml_attribute::set_value at pugixml.cpp:5482:35 in pugixml.hpp
// pugi::xml_node::append_child at pugixml.cpp:6323:34 in pugixml.hpp
// pugi::xml_node::append_attribute at pugixml.cpp:6041:39 in pugixml.hpp
// pugi::xml_node::append_attribute at pugixml.cpp:6041:39 in pugixml.hpp
// pugi::xml_node::remove_attribute at pugixml.cpp:6535:30 in pugixml.hpp
// pugi::xml_node::remove_attribute at pugixml.cpp:6535:30 in pugixml.hpp
// pugi::xml_node::remove_attribute at pugixml.cpp:6535:30 in pugixml.hpp
// pugi::xml_node::remove_attribute at pugixml.cpp:6535:30 in pugixml.hpp
// pugi::xml_node::append_attribute at pugixml.cpp:6041:39 in pugixml.hpp
// pugi::xml_node::append_attribute at pugixml.cpp:6041:39 in pugixml.hpp
// pugi::xml_node::remove_attribute at pugixml.cpp:6535:30 in pugixml.hpp
// pugi::xml_node::remove_attribute at pugixml.cpp:6535:30 in pugixml.hpp
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

static void test_xml_attribute_functions(pugi::xml_attribute& attr, const char* name_str, const char* value_str, const char* default_str) {
    // Test xml_attribute::as_string
    if (default_str) {
        attr.as_string(default_str);
    } else {
        attr.as_string("");
    }
    
    // Test xml_attribute::name
    attr.name();
    
    // Test xml_attribute::value
    attr.value();
    
    // Test xml_attribute::set_name - only if name_str is not null
    if (name_str) {
        attr.set_name(name_str);
    }
    
    // Test xml_attribute::set_value - only if value_str is not null
    if (value_str) {
        attr.set_value(value_str);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    
    // Create a document and node to work with
    pugi::xml_document doc;
    pugi::xml_node node = doc.append_child("test_node");
    
    // Create strings from fuzzer input
    std::string input_str(reinterpret_cast<const char*>(Data), Size);
    
    // Split input into parts for different string parameters
    size_t half = Size / 2;
    std::string first_part(reinterpret_cast<const char*>(Data), half);
    std::string second_part(reinterpret_cast<const char*>(Data + half), Size - half);
    
    // Create attributes for testing
    pugi::xml_attribute attr1 = node.append_attribute("attr1");
    pugi::xml_attribute attr2 = node.append_attribute("attr2");
    
    // Test with various string combinations
    test_xml_attribute_functions(attr1, first_part.c_str(), second_part.c_str(), "default");
    test_xml_attribute_functions(attr2, second_part.c_str(), first_part.c_str(), input_str.c_str());
    
    // Test xml_node::remove_attribute with different names
    if (!first_part.empty()) {
        node.remove_attribute(first_part.c_str());
    }
    if (!second_part.empty()) {
        node.remove_attribute(second_part.c_str());
    }
    node.remove_attribute("attr1");
    node.remove_attribute("attr2");
    
    // Test with empty strings
    test_xml_attribute_functions(attr1, "", "", "");
    
    // Create new attributes and test again
    pugi::xml_attribute attr3 = node.append_attribute("");
    pugi::xml_attribute attr4 = node.append_attribute(input_str.c_str());
    
    test_xml_attribute_functions(attr3, first_part.c_str(), second_part.c_str(), "");
    test_xml_attribute_functions(attr4, "", "", "");
    
    // Test remove_attribute on newly created attributes
    node.remove_attribute("");
    if (!input_str.empty()) {
        node.remove_attribute(input_str.c_str());
    }
    
    return 0;
}