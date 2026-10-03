// This fuzz driver is generated for library pugixml, aiming to fuzz the following functions:
// pugi::xml_document::load_buffer at pugixml.cpp:7749:46 in pugixml.hpp
// pugi::xpath_query::evaluate_node_set at pugixml.cpp:13384:43 in pugixml.hpp
// pugi::xpath_node_set::begin at pugixml.cpp:12885:62 in pugixml.hpp
// pugi::xpath_node_set::type at pugixml.cpp:12864:54 in pugixml.hpp
// pugi::xpath_node_set::empty at pugixml.cpp:12874:36 in pugixml.hpp
// pugi::xpath_node_set::first at pugixml.cpp:12900:42 in pugixml.hpp
// pugi::xpath_node_set::end at pugixml.cpp:12890:62 in pugixml.hpp
// pugi::xpath_node_set::size at pugixml.cpp:12869:38 in pugixml.hpp
// pugi::xpath_node_set::begin at pugixml.cpp:12885:62 in pugixml.hpp
// pugi::xpath_node_set::end at pugixml.cpp:12890:62 in pugixml.hpp
// pugi::xpath_node::node at pugixml.cpp:12720:36 in pugixml.hpp
// pugi::xpath_node::attribute at pugixml.cpp:12725:41 in pugixml.hpp
// pugi::xml_node::name at pugixml.cpp:5688:39 in pugixml.hpp
// pugi::xml_node::type at pugixml.cpp:5695:39 in pugixml.hpp
// pugi::xml_attribute::name at pugixml.cpp:5365:44 in pugixml.hpp
// pugi::xml_attribute::value at pugixml.cpp:5372:44 in pugixml.hpp
// pugi::xpath_node_set::begin at pugixml.cpp:12885:62 in pugixml.hpp
// pugi::xpath_node_set::type at pugixml.cpp:12864:54 in pugixml.hpp
// pugi::xpath_node_set::empty at pugixml.cpp:12874:36 in pugixml.hpp
// pugi::xpath_node_set::first at pugixml.cpp:12900:42 in pugixml.hpp
// pugi::xpath_node_set::end at pugixml.cpp:12890:62 in pugixml.hpp
// pugi::xpath_node_set::size at pugixml.cpp:12869:38 in pugixml.hpp
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

static pugi::xpath_node_set create_xpath_node_set_from_data(const uint8_t* data, size_t size) {
    // Create a simple XML document from fuzzer data
    pugi::xml_document doc;
    
    // Try to load XML from buffer
    pugi::xml_parse_result result = doc.load_buffer(data, size);
    
    if (!result) {
        // If parsing fails, return empty set
        return pugi::xpath_node_set();
    }
    
    // Create an XPath query that selects all nodes
    pugi::xpath_query query("//*");
    
    // Evaluate the query to get a node set
    pugi::xpath_node_set node_set = query.evaluate_node_set(doc);
    
    return node_set;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    // Create xpath_node_set from fuzzer input
    pugi::xpath_node_set node_set = create_xpath_node_set_from_data(Data, Size);
    
    // Test all the target API functions
    // 1. begin()
    pugi::xpath_node_set::const_iterator begin_iter = node_set.begin();
    
    // 2. type()
    pugi::xpath_node_set::type_t set_type = node_set.type();
    
    // 3. empty()
    bool is_empty = node_set.empty();
    
    // 4. first()
    pugi::xpath_node first_node = node_set.first();
    
    // 5. end()
    pugi::xpath_node_set::const_iterator end_iter = node_set.end();
    
    // 6. size()
    size_t set_size = node_set.size();
    
    // Additional exploration: iterate through the set if not empty
    if (!is_empty) {
        // Test iterator operations
        for (pugi::xpath_node_set::const_iterator it = node_set.begin(); it != node_set.end(); ++it) {
            // Access node and attribute from iterator
            pugi::xml_node node = it->node();
            pugi::xml_attribute attr = it->attribute();
            
            // Test node operations
            if (node) {
                const char* name = node.name();
                pugi::xml_node_type type = node.type();
            }
            
            // Test attribute operations
            if (attr) {
                const char* attr_name = attr.name();
                const char* attr_value = attr.value();
            }
        }
        
        // Test copy constructor
        pugi::xpath_node_set copied_set(node_set);
        
        // Test functions on copied set
        pugi::xpath_node_set::const_iterator copied_begin = copied_set.begin();
        pugi::xpath_node_set::type_t copied_type = copied_set.type();
        bool copied_empty = copied_set.empty();
        pugi::xpath_node copied_first = copied_set.first();
        pugi::xpath_node_set::const_iterator copied_end = copied_set.end();
        size_t copied_size = copied_set.size();
    }
    
    // Test with empty xpath_node
    pugi::xpath_node empty_xpath_node;
    
    // Test with empty xml_node
    pugi::xml_node empty_node;
    pugi::xpath_node xpath_from_empty(empty_node);
    
    // Test with empty xml_attribute
    pugi::xml_attribute empty_attr;
    
    return 0;
}