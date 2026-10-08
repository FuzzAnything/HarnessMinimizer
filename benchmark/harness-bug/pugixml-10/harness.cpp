// This fuzz driver is generated for library pugixml, aiming to fuzz the following functions:
// pugi::xpath_node::attribute at pugixml.cpp:12725:41 in pugixml.hpp
// pugi::xpath_node::parent at pugixml.cpp:12730:36 in pugixml.hpp
// pugi::xpath_node::node at pugixml.cpp:12720:36 in pugixml.hpp
// pugi::xml_node::root at pugixml.cpp:5918:34 in pugixml.hpp
// pugi::xml_document::load_string at pugixml.cpp:7712:46 in pugixml.hpp
// pugi::xml_node::select_nodes at pugixml.cpp:13458:40 in pugixml.hpp
// pugi::xml_document::load_string at pugixml.cpp:7712:46 in pugixml.hpp
// pugi::xml_node::child at pugixml.cpp:5707:34 in pugixml.hpp
// pugi::xml_node::child at pugixml.cpp:5707:34 in pugixml.hpp
// pugi::xml_node::child at pugixml.cpp:5707:34 in pugixml.hpp
// pugi::xml_node::attribute at pugixml.cpp:5721:39 in pugixml.hpp
// pugi::xml_node::child at pugixml.cpp:5707:34 in pugixml.hpp
// pugi::xpath_node_set::type at pugixml.cpp:12864:54 in pugixml.hpp
// pugi::xpath_node_set::sort at pugixml.cpp:12895:36 in pugixml.hpp
// pugi::xpath_node_set::empty at pugixml.cpp:12874:36 in pugixml.hpp
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
#include <cstring>

static pugi::xpath_node_set create_test_nodeset(const uint8_t* data, size_t size) {
    pugi::xml_document doc;
    
    // Create a minimal XML structure to work with
    const char* xml_content = 
        "<?xml version=\"1.0\"?>"
        "<root>"
        "  <element attr=\"value1\">text1</element>"
        "  <element attr=\"value2\">text2</element>"
        "  <element attr=\"value3\">text3</element>"
        "</root>";
    
    pugi::xml_parse_result result = doc.load_string(xml_content);
    if (!result) {
        return pugi::xpath_node_set();
    }
    
    // Create xpath_node_set by evaluating an XPath query
    try {
        pugi::xpath_node_set nodeset = doc.select_nodes("//* | //@*");
        return nodeset;
    } catch (...) {
        return pugi::xpath_node_set();
    }
}

static pugi::xpath_node create_test_xpath_node(const uint8_t* data, size_t size) {
    pugi::xml_document doc;
    
    // Create a minimal XML structure
    const char* xml_content = 
        "<?xml version=\"1.0\"?>"
        "<root>"
        "  <element id=\"1\">Text content</element>"
        "  <another>More text</another>"
        "</root>";
    
    pugi::xml_parse_result result = doc.load_string(xml_content);
    if (!result) {
        return pugi::xpath_node();
    }
    
    // Create different types of xpath_nodes based on input data
    if (size > 0) {
        uint8_t selector = data[0] % 3;
        
        pugi::xml_node root = doc.child("root");
        if (root) {
            if (selector == 0) {
                // Return a node xpath_node
                return pugi::xpath_node(root.child("element"));
            } else if (selector == 1) {
                // Return an attribute xpath_node
                pugi::xml_node elem = root.child("element");
                if (elem) {
                    return pugi::xpath_node(elem.attribute("id"), elem);
                }
            } else {
                // Return another node xpath_node
                return pugi::xpath_node(root.child("another"));
            }
        }
    }
    
    return pugi::xpath_node();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create test xpath_node_set
    pugi::xpath_node_set nodeset = create_test_nodeset(Data, Size);
    
    // 1. Call pugi::xpath_node_set::type
    pugi::xpath_node_set::type_t node_type = nodeset.type();
    (void)node_type; // Avoid unused variable warning
    
    // 2. Call pugi::xpath_node_set::sort
    // Use data to determine sort direction
    bool reverse = false;
    if (Size > 0) {
        reverse = (Data[0] % 2) == 0;
    }
    nodeset.sort(reverse);
    
    // 3. Call pugi::xpath_node_set::empty
    bool is_empty = nodeset.empty();
    (void)is_empty; // Avoid unused variable warning
    
    // Create test xpath_node
    pugi::xpath_node xnode = create_test_xpath_node(Data, Size);
    
    // 4. Call pugi::xpath_node::attribute
    pugi::xml_attribute attr = xnode.attribute();
    (void)attr; // Avoid unused variable warning
    
    // 5. Call pugi::xpath_node::parent
    pugi::xml_node parent = xnode.parent();
    (void)parent; // Avoid unused variable warning
    
    // 6. Call pugi::xpath_node::node
    pugi::xml_node node = xnode.node();
    
    // 7. Call pugi::xml_node::root
    if (node) {
        pugi::xml_node root = node.root();
        (void)root; // Avoid unused variable warning
    }
    
    return 0;
}