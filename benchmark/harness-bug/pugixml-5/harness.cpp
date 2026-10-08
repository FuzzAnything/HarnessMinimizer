#include <fuzzer/FuzzedDataProvider.h>
#include "pugixml.hpp"

#include <stdint.h>
#include <string>
#include <vector>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size for comprehensive xml_text testing
    // We need enough data for various numeric values, strings, and operations
    if (size < 128) return 0;
    
    FuzzedDataProvider fdp(data, size);
    
    // Step 1: Create XML document structure for testing
    pugi::xml_document doc;
    
    // Create a root node
    std::string root_name = fdp.ConsumeRandomLengthString(20);
    pugi::xml_node root = doc.append_child(pugi::node_element);
    root.set_name(root_name.c_str());
    
    // Step 2: Create multiple text nodes with different characteristics
    // We'll create several nodes to test various xml_text operations
    
    std::vector<pugi::xml_node> text_nodes;
    
    // Create 5-10 text nodes for comprehensive testing
    int node_count = fdp.ConsumeIntegralInRange<int>(5, 10);
    
    for (int i = 0; i < node_count && fdp.remaining_bytes() > 50; ++i) {
        // Create element node
        std::string elem_name = fdp.ConsumeRandomLengthString(15);
        pugi::xml_node elem = root.append_child(elem_name.c_str());
        
        // Create text child node
        pugi::xml_node text_node = elem.append_child(pugi::node_pcdata);
        text_nodes.push_back(elem); // Store element for text access
    }
    
    if (text_nodes.empty()) {
        return 0; // No nodes to test
    }
    
    // Step 3: Test xml_text APIs comprehensively
    
    // 3.1 Test basic xml_text retrieval and empty() method
    for (auto& node : text_nodes) {
        pugi::xml_text text_obj = node.text();
        
        // Test empty() on newly created text nodes (should be true initially)
        bool is_empty = text_obj.empty();
        (void)is_empty; // Use to avoid unused variable warning
        
        // Test operator bool conversion
        if (text_obj) {
            // Valid text object
        }
        
        // Test operator! 
        if (!text_obj) {
            // Empty text object
        }
    }
    
    // 3.2 Test set() methods with various data types
    // Consume operation types from fuzzer input
    int set_operation_count = fdp.ConsumeIntegralInRange<int>(10, 30);
    
    for (int i = 0; i < set_operation_count && fdp.remaining_bytes() > 20 && !text_nodes.empty(); ++i) {
        // Select a random node
        size_t node_idx = fdp.ConsumeIntegralInRange<size_t>(0, text_nodes.size() - 1);
        pugi::xml_text text_obj = text_nodes[node_idx].text();
        
        // Select operation type
        int op_type = fdp.ConsumeIntegralInRange<int>(0, 12);
        
        switch (op_type) {
            case 0: { // set(const char_t*)
                std::string str_val = fdp.ConsumeRandomLengthString(100);
                text_obj.set(str_val.c_str());
                break;
            }
            case 1: { // set(const char_t*, size_t)
                std::string str_val = fdp.ConsumeRandomLengthString(100);
                text_obj.set(str_val.c_str(), str_val.length());
                break;
            }
            case 2: { // set(int)
                int int_val = fdp.ConsumeIntegral<int>();
                text_obj.set(int_val);
                break;
            }
            case 3: { // set(unsigned int)
                unsigned int uint_val = fdp.ConsumeIntegral<unsigned int>();
                text_obj.set(uint_val);
                break;
            }
            case 4: { // set(long)
                long long_val = fdp.ConsumeIntegral<long>();
                text_obj.set(long_val);
                break;
            }
            case 5: { // set(unsigned long)
                unsigned long ulong_val = fdp.ConsumeIntegral<unsigned long>();
                text_obj.set(ulong_val);
                break;
            }
            case 6: { // set(double)
                double double_val = fdp.ConsumeFloatingPoint<double>();
                text_obj.set(double_val);
                break;
            }
            case 7: { // set(double, int precision)
                double double_val = fdp.ConsumeFloatingPoint<double>();
                int precision = fdp.ConsumeIntegralInRange<int>(-10, 20);
                text_obj.set(double_val, precision);
                break;
            }
            case 8: { // set(float)
                float float_val = fdp.ConsumeFloatingPoint<float>();
                text_obj.set(float_val);
                break;
            }
            case 9: { // set(float, int precision)
                float float_val = fdp.ConsumeFloatingPoint<float>();
                int precision = fdp.ConsumeIntegralInRange<int>(-10, 20);
                text_obj.set(float_val, precision);
                break;
            }
            case 10: { // set(bool)
                bool bool_val = fdp.ConsumeBool();
                text_obj.set(bool_val);
                break;
            }
#ifdef PUGIXML_HAS_LONG_LONG
            case 11: { // set(long long)
                long long llong_val = fdp.ConsumeIntegral<long long>();
                text_obj.set(llong_val);
                break;
            }
            case 12: { // set(unsigned long long)
                unsigned long long ullong_val = fdp.ConsumeIntegral<unsigned long long>();
                text_obj.set(ullong_val);
                break;
            }
#endif
        }
    }
    
    // 3.3 Test operator= overloads
    int assign_operation_count = fdp.ConsumeIntegralInRange<int>(5, 20);
    
    for (int i = 0; i < assign_operation_count && fdp.remaining_bytes() > 20 && !text_nodes.empty(); ++i) {
        size_t node_idx = fdp.ConsumeIntegralInRange<size_t>(0, text_nodes.size() - 1);
        pugi::xml_text text_obj = text_nodes[node_idx].text();
        
        int op_type = fdp.ConsumeIntegralInRange<int>(0, 10);
        
        switch (op_type) {
            case 0: {
                std::string str_val = fdp.ConsumeRandomLengthString(100);
                text_obj = str_val.c_str();
                break;
            }
            case 1: {
                int int_val = fdp.ConsumeIntegral<int>();
                text_obj = int_val;
                break;
            }
            case 2: {
                unsigned int uint_val = fdp.ConsumeIntegral<unsigned int>();
                text_obj = uint_val;
                break;
            }
            case 3: {
                long long_val = fdp.ConsumeIntegral<long>();
                text_obj = long_val;
                break;
            }
            case 4: {
                unsigned long ulong_val = fdp.ConsumeIntegral<unsigned long>();
                text_obj = ulong_val;
                break;
            }
            case 5: {
                double double_val = fdp.ConsumeFloatingPoint<double>();
                text_obj = double_val;
                break;
            }
            case 6: {
                float float_val = fdp.ConsumeFloatingPoint<float>();
                text_obj = float_val;
                break;
            }
            case 7: {
                bool bool_val = fdp.ConsumeBool();
                text_obj = bool_val;
                break;
            }
#ifdef PUGIXML_HAS_STRING_VIEW
            case 8: {
                std::string str_val = fdp.ConsumeRandomLengthString(100);
                std::string_view sv_val = str_val;
                text_obj = sv_val;
                break;
            }
#endif
#ifdef PUGIXML_HAS_LONG_LONG
            case 9: {
                long long llong_val = fdp.ConsumeIntegral<long long>();
                text_obj = llong_val;
                break;
            }
            case 10: {
                unsigned long long ullong_val = fdp.ConsumeIntegral<unsigned long long>();
                text_obj = ullong_val;
                break;
            }
#endif
        }
    }
    
    // 3.4 Test get() and as_*() retrieval methods
    // First, ensure we have some text content in nodes
    if (!text_nodes.empty() && fdp.remaining_bytes() > 50) {
        // Set some text in a few nodes for retrieval testing
        for (int i = 0; i < 3 && i < text_nodes.size(); ++i) {
            std::string test_text = fdp.ConsumeRandomLengthString(50);
            text_nodes[i].text().set(test_text.c_str());
        }
        
        // Also set some numeric values for conversion testing
        if (text_nodes.size() > 3 && fdp.remaining_bytes() > 30) {
            text_nodes[3].text().set(42); // int
            text_nodes[4].text().set(3.14159); // double
            text_nodes[5].text().set(true); // bool
        }
    }
    
    // Now test retrieval methods on all nodes
    for (auto& node : text_nodes) {
        pugi::xml_text text_obj = node.text();
        
        // Test get() method
        const char* text_value = text_obj.get();
        (void)text_value;
        
        // Test as_string() with and without default value
        std::string default_str = fdp.ConsumeRandomLengthString(20);
        const char* str_result = text_obj.as_string();
        const char* str_with_default = text_obj.as_string(default_str.c_str());
        (void)str_result;
        (void)str_with_default;
        
        // Test as_int() with and without default value
        int int_default = fdp.ConsumeIntegral<int>();
        int int_result = text_obj.as_int();
        int int_with_default = text_obj.as_int(int_default);
        (void)int_result;
        (void)int_with_default;
        
        // Test as_uint() with and without default value
        unsigned int uint_default = fdp.ConsumeIntegral<unsigned int>();
        unsigned int uint_result = text_obj.as_uint();
        unsigned int uint_with_default = text_obj.as_uint(uint_default);
        (void)uint_result;
        (void)uint_with_default;
        
        // Test as_double() with and without default value
        double double_default = fdp.ConsumeFloatingPoint<double>();
        double double_result = text_obj.as_double();
        double double_with_default = text_obj.as_double(double_default);
        (void)double_result;
        (void)double_with_default;
        
        // Test as_float() with and without default value
        float float_default = fdp.ConsumeFloatingPoint<float>();
        float float_result = text_obj.as_float();
        float float_with_default = text_obj.as_float(float_default);
        (void)float_result;
        (void)float_with_default;
        
        // Test as_bool() with and without default value
        bool bool_default = fdp.ConsumeBool();
        bool bool_result = text_obj.as_bool();
        bool bool_with_default = text_obj.as_bool(bool_default);
        (void)bool_result;
        (void)bool_with_default;
        
#ifdef PUGIXML_HAS_LONG_LONG
        // Test as_llong() with and without default value
        long long llong_default = fdp.ConsumeIntegral<long long>();
        long long llong_result = text_obj.as_llong();
        long long llong_with_default = text_obj.as_llong(llong_default);
        (void)llong_result;
        (void)llong_with_default;
        
        // Test as_ullong() with and without default value
        unsigned long long ullong_default = fdp.ConsumeIntegral<unsigned long long>();
        unsigned long long ullong_result = text_obj.as_ullong();
        unsigned long long ullong_with_default = text_obj.as_ullong(ullong_default);
        (void)ullong_result;
        (void)ullong_with_default;
#endif
        
        // Test data() method to get underlying node
        pugi::xml_node data_node = text_obj.data();
        (void)data_node;
    }
    
    // 3.5 Test edge cases with empty xml_text objects
    // Create empty xml_text objects
    pugi::xml_text empty_text1;
    pugi::xml_text empty_text2;
    
    // Test empty() on truly empty objects
    bool empty1 = empty_text1.empty();
    bool empty2 = empty_text2.empty();
    (void)empty1;
    (void)empty2;
    
    // Test get() on empty objects (should return "")
    const char* empty_get = empty_text1.get();
    (void)empty_get;
    
    // Test as_*() methods with default values on empty objects
    std::string empty_default_str = "default";
    const char* empty_str = empty_text1.as_string(empty_default_str.c_str());
    (void)empty_str;
    
    int empty_int = empty_text1.as_int(999);
    (void)empty_int;
    
    double empty_double = empty_text1.as_double(3.14);
    (void)empty_double;
    
    bool empty_bool = empty_text1.as_bool(true);
    (void)empty_bool;
    
    // Test that set() fails on empty objects
    std::string test_set = "should_fail";
    bool set_result = empty_text1.set(test_set.c_str());
    (void)set_result;
    
    // 3.6 Test xml_text with CDATA nodes
    if (fdp.remaining_bytes() > 50) {
        pugi::xml_node cdata_node = root.append_child(pugi::node_cdata);
        std::string cdata_content = fdp.ConsumeRandomLengthString(100);
        cdata_node.set_value(cdata_content.c_str());
        
        // Get xml_text from CDATA node
        pugi::xml_text cdata_text = cdata_node.text();
        if (!cdata_text.empty()) {
            const char* cdata_value = cdata_text.get();
            (void)cdata_value;
            
            // Try to modify CDATA text
            std::string new_cdata = fdp.ConsumeRandomLengthString(50);
            cdata_text.set(new_cdata.c_str());
        }
    }
    
    // 3.7 Test string_view support if available
#ifdef PUGIXML_HAS_STRING_VIEW
    if (fdp.remaining_bytes() > 100 && !text_nodes.empty()) {
        pugi::xml_text text_obj = text_nodes[0].text();
        
        std::string sv_str = fdp.ConsumeRandomLengthString(80);
        std::string_view sv = sv_str;
        
        // Test set() with string_view
        text_obj.set(sv);
        
        // Test operator= with string_view  
        text_obj = sv;
    }
#endif
    
    // 3.8 Test the global operators for Borland compatibility
    // These are declared but may not be used in normal code
#ifdef __BORLANDC__
    if (!text_nodes.empty()) {
        pugi::xml_text text_obj = text_nodes[0].text();
        bool test_and = text_obj && true;
        bool test_or = text_obj || false;
        (void)test_and;
        (void)test_or;
    }
#endif
    
    return 0;
}
