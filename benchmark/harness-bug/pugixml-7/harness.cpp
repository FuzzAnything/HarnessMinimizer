#include <fuzzer/FuzzedDataProvider.h>
#include "pugixml.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check: need enough for XML structure, search queries, and attributes
    if (size < 256) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    
    // ==================== PHASE 1: CREATE COMPLEX XML STRUCTURE FOR SEARCH TESTING ====================
    // Build a rich XML document with multiple levels, diverse attributes, and varied content
    pugi::xml_document doc;
    
    // Create root element
    pugi::xml_node root = doc.append_child("search_test_root");
    
    // Add metadata attributes to root
    root.append_attribute("version") = "1.0";
    root.append_attribute("encoding") = "UTF-8";
    root.append_attribute("test_type") = "advanced_search";
    
    // Track created nodes for later search operations
    std::vector<pugi::xml_node> searchable_nodes;
    std::vector<std::string> node_paths;
    
    // Create multiple levels of hierarchy with diverse attributes
    int level1_count = fdp.ConsumeIntegralInRange<int>(3, 8);
    for (int i = 0; i < level1_count && fdp.remaining_bytes() > 50; ++i) {
        std::string level1_name = "level1_" + std::to_string(i);
        pugi::xml_node level1_node = root.append_child(level1_name.c_str());
        searchable_nodes.push_back(level1_node);
        
        // Add diverse attributes for attribute-based searching
        std::string id_value = "id_" + std::to_string(i * 100);
        level1_node.append_attribute("id") = id_value.c_str();
        
        std::string type_value = (i % 3 == 0) ? "type_a" : (i % 3 == 1) ? "type_b" : "type_c";
        level1_node.append_attribute("type") = type_value.c_str();
        
        std::string category_value = (i % 2 == 0) ? "category_even" : "category_odd";
        level1_node.append_attribute("category") = category_value.c_str();
        
        std::string priority_value = std::to_string(i % 5 + 1);
        level1_node.append_attribute("priority") = priority_value.c_str();
        
        // Add text content
        std::string level1_text = fdp.ConsumeRandomLengthString(100);
        level1_node.text() = level1_text.c_str();
        
        // Create second level children
        int level2_count = fdp.ConsumeIntegralInRange<int>(2, 6);
        for (int j = 0; j < level2_count && fdp.remaining_bytes() > 30; ++j) {
            std::string level2_name = "level2_" + std::to_string(i) + "_" + std::to_string(j);
            pugi::xml_node level2_node = level1_node.append_child(level2_name.c_str());
            searchable_nodes.push_back(level2_node);
            
            // Add attributes with varying patterns
            std::string level2_id = "id_" + std::to_string(i * 100 + j * 10);
            level2_node.append_attribute("id") = level2_id.c_str();
            
            // Use different attribute names for testing find_child_by_attribute
            if (j % 2 == 0) {
                level2_node.append_attribute("special") = "yes";
                level2_node.append_attribute("flags") = "set";
            }
            
            if (j % 3 == 0) {
                std::string unique_attr = fdp.ConsumeRandomLengthString(20);
                std::string unique_value = fdp.ConsumeRandomLengthString(40);
                level2_node.append_attribute(unique_attr.c_str()) = unique_value.c_str();
            }
            
            // Create third level for deep path testing
            if (j % 4 == 0 && fdp.remaining_bytes() > 20) {
                std::string level3_name = "level3_" + std::to_string(i) + "_" + std::to_string(j);
                pugi::xml_node level3_node = level2_node.append_child(level3_name.c_str());
                searchable_nodes.push_back(level3_node);
                
                level3_node.append_attribute("depth") = "3";
                level3_node.append_attribute("final") = "true";
                
                std::string level3_text = fdp.ConsumeRandomLengthString(80);
                level3_node.text() = level3_text.c_str();
            }
        }
    }
    // ==================== PHASE 2: NODE PATH GENERATION TESTING ====================
    // TARGET: xml_node::path(char delimiter) const - returns node path as std::string
    
#ifndef PUGIXML_NO_STL
    if (!searchable_nodes.empty()) {
        // Test path() on various nodes with different delimiters
        for (size_t i = 0; i < std::min(searchable_nodes.size(), size_t(10)); ++i) {
            pugi::xml_node node = searchable_nodes[i];
            
            // Test with default delimiter '/'
            std::string path_default = node.path();
            
            // Test with different delimiters from fuzzer input
            char delimiter1 = fdp.ConsumeIntegral<char>();
            std::string path_custom1 = node.path(delimiter1);
            
            // Test with printable delimiter
            char delimiter2 = fdp.ConsumeIntegralInRange<char>('!', '~');
            std::string path_custom2 = node.path(delimiter2);
            
            // Test with dot delimiter (common alternative)
            std::string path_dot = node.path('.');
            
            // Store paths for potential use in XPath queries
            node_paths.push_back(path_default);
        }
        
        // Test path() on root node
        std::string root_path_default = root.path();
        char root_delimiter = fdp.ConsumeIntegralInRange<char>('!', '~');
        std::string root_path_custom = root.path(root_delimiter);
    }
#endif // PUGIXML_NO_STL
#ifndef PUGIXML_NO_XPATH
    try {
        // ==================== PHASE 3: XPATH_QUERY CREATION FOR SELECT_SINGLE_NODE ====================
        // Create various XPath queries for testing select_single_node with xpath_query objects
        
        std::vector<std::string> xpath_expressions;
        
        // Generate XPath expressions from fuzzer input
        int num_expressions = fdp.ConsumeIntegralInRange<int>(5, 20);
        for (int i = 0; i < num_expressions && fdp.remaining_bytes() > 10; ++i) {
            std::string xpath_expr = fdp.ConsumeRandomLengthString(100);
            if (!xpath_expr.empty()) {
                xpath_expressions.push_back(xpath_expr);
            }
        }
        
        // Add structured XPath expressions for systematic testing
        xpath_expressions.push_back("//*[@id]");
        xpath_expressions.push_back("//*[@type='type_a']");
        xpath_expressions.push_back("//*[@category='category_even']");
        xpath_expressions.push_back("//level1_0");
        xpath_expressions.push_back("//level2_0_0");
        xpath_expressions.push_back("/search_test_root");
        xpath_expressions.push_back("//*[text()]");
        xpath_expressions.push_back("//*[@priority > '2']");
        xpath_expressions.push_back("//*[@special='yes']");
        xpath_expressions.push_back("//*[contains(@id, '_1')]");
        
        // Create xpath_query objects and test select_single_node
        for (const auto& expr : xpath_expressions) {
            if (expr.empty() || fdp.remaining_bytes() < 5) continue;
            
            // Create xpath_query object
            pugi::xpath_query query(expr.c_str());
            
            // Check if query compilation succeeded
            if (!query) {
                // Query compilation failed - test error handling
                const pugi::xpath_parse_result& result = query.result();
                continue;
            }
            
            // TARGET: Test xml_node::select_single_node(const xpath_query&)
            // Use the deprecated API specifically as identified in coverage gap
            pugi::xpath_node selected = root.select_single_node(query);
            
            // Also test on other nodes for different contexts
            for (size_t i = 0; i < std::min(searchable_nodes.size(), size_t(5)); ++i) {
                pugi::xpath_node selected_from_node = searchable_nodes[i].select_single_node(query);
            }
            
            // Test with empty/null nodes
            pugi::xml_node empty_node;
            pugi::xpath_node selected_from_empty = empty_node.select_single_node(query);
        }
        
        // ==================== PHASE 4: ATTRIBUTE-BASED CHILD SEARCH TESTING ====================
        // TARGET: xml_node::find_child_by_attribute with various parameter combinations
        
        // Generate attribute search parameters from fuzzer input
        while (fdp.remaining_bytes() > 50) {
            uint8_t search_type = fdp.ConsumeIntegral<uint8_t>() % 4;
            
            switch (search_type) {
                case 0: {
                    // Test find_child_by_attribute(const char* name, const char* attr_name, const char* attr_value)
                    std::string node_name = fdp.ConsumeRandomLengthString(30);
                    std::string attr_name = fdp.ConsumeRandomLengthString(30);
                    std::string attr_value = fdp.ConsumeRandomLengthString(50);
                    
                    pugi::xml_node found = root.find_child_by_attribute(
                        node_name.c_str(), 
                        attr_name.c_str(), 
                        attr_value.c_str()
                    );
                    
                    // Also test on child nodes
                    for (size_t i = 0; i < std::min(searchable_nodes.size(), size_t(3)); ++i) {
                        pugi::xml_node found_in_child = searchable_nodes[i].find_child_by_attribute(
                            node_name.c_str(),
                            attr_name.c_str(),
                            attr_value.c_str()
                        );
                    }
                    break;
                }
                
                case 1: {
                    // Test find_child_by_attribute(const char* attr_name, const char* attr_value)
                    std::string attr_name = fdp.ConsumeRandomLengthString(30);
                    std::string attr_value = fdp.ConsumeRandomLengthString(50);
                    
                    pugi::xml_node found = root.find_child_by_attribute(
                        attr_name.c_str(),
                        attr_value.c_str()
                    );
                    
                    // Test with known attribute values from our document
                    pugi::xml_node found_by_id = root.find_child_by_attribute("id", "id_100");
                    pugi::xml_node found_by_type = root.find_child_by_attribute("type", "type_a");
                    pugi::xml_node found_by_category = root.find_child_by_attribute("category", "category_even");
                    pugi::xml_node found_by_priority = root.find_child_by_attribute("priority", "3");
                    
                    break;
                }
                
                case 2: {
                    // Test with empty/null attribute values (edge cases)
                    std::string attr_name = fdp.ConsumeRandomLengthString(20);
                    
                    // Test with empty attribute value
                    pugi::xml_node found_empty = root.find_child_by_attribute(attr_name.c_str(), "");
                    
                    // Test with null pointers (should handle gracefully)
                    pugi::xml_node found_null_name = root.find_child_by_attribute(nullptr, "some_value");
                    pugi::xml_node found_null_value = root.find_child_by_attribute("some_name", nullptr);
                    pugi::xml_node found_null_both = root.find_child_by_attribute(nullptr, nullptr);
                    
                    break;
                }
                
                case 3: {
                    // Test integrated search: find by attribute, then get path, then use in XPath
                    std::string search_attr = fdp.ConsumeRandomLengthString(20);
                    std::string search_value = fdp.ConsumeRandomLengthString(30);
                    
                    pugi::xml_node found_node = root.find_child_by_attribute(
                        search_attr.c_str(),
                        search_value.c_str()
                    );
                    
                    if (found_node) {
                        // Get path of found node
                        char path_delimiter = fdp.ConsumeIntegralInRange<char>('!', '~');
                        std::string found_path = found_node.path(path_delimiter);
                        
                        // Use the found node as context for XPath query
                        std::string xpath_expr = fdp.ConsumeRandomLengthString(80);
                        if (!xpath_expr.empty()) {
                            pugi::xpath_query query(xpath_expr.c_str());
                            if (query) {
                                pugi::xpath_node selected = found_node.select_single_node(query);
                            }
                        }
                    }
                    break;
                }
            }
            
            // Break if we're running low on input
            if (fdp.remaining_bytes() < 100) break;
        }
        
        // ==================== PHASE 5: COMPREHENSIVE SEARCH OPERATIONS INTEGRATION ====================
        // Test combinations of search operations in realistic scenarios
        
        // Scenario 1: Chain multiple search operations
        if (fdp.remaining_bytes() > 100) {
            // First find a node by attribute
            pugi::xml_node first_found = root.find_child_by_attribute("type", "type_b");
            
            if (first_found) {
                // Get its path
                std::string first_path = first_found.path('>');
                
                // Use XPath to find related nodes
                pugi::xpath_query query1("//*[@category='category_odd']");
                if (query1) {
                    pugi::xpath_node xpath_result = first_found.select_single_node(query1);
                }
                
                // Search within found node
                pugi::xml_node nested_found = first_found.find_child_by_attribute("special", "yes");
                
                if (nested_found) {
                    std::string nested_path = nested_found.path(':');
                }
            }
        }
        
        // Scenario 2: Test path-based XPath expressions
        if (!node_paths.empty() && fdp.remaining_bytes() > 50) {
            for (const auto& path_str : node_paths) {
                if (path_str.empty()) continue;
                
                // Convert path to XPath expression
                std::string xpath_from_path = path_str;
                std::replace(xpath_from_path.begin(), xpath_from_path.end(), '/', '/');
                
                pugi::xpath_query path_query(xpath_from_path.c_str());
                if (path_query) {
                    pugi::xpath_node path_result = root.select_single_node(path_query);
                }
            }
        }
        
    } catch (...) {
        // Catch any exceptions from XPath operations
        // Fuzzer should handle exceptions gracefully
    }
#endif // PUGIXML_NO_XPATH
    
    // ==================== PHASE 6: CLEANUP AND FINALIZATION ====================
    // Document cleanup happens automatically via destructors
    
    // Reset document to test cleanup paths
    doc.reset();
    
    return 0;
}
