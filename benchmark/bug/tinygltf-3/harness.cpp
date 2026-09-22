// This fuzz driver is generated for library tinygltf, aiming to fuzz the following functions:
// tinygltf::DecodeDataURI at tiny_gltf.cc:1732:6 in tiny_gltf.h
// tinygltf::DecodeDataURI at tiny_gltf.cc:1732:6 in tiny_gltf.h
// tinygltf::WriteImageData at tiny_gltf.cc:1120:6 in tiny_gltf.h
// tinygltf::WriteImageData at tiny_gltf.cc:1120:6 in tiny_gltf.h
// tinygltf::WriteImageData at tiny_gltf.cc:1120:6 in tiny_gltf.h
// tinygltf::TinyGLTF::SetFsCallbacks at tiny_gltf.cc:1225:16 in tiny_gltf.h
// tinygltf::TinyGLTF::SetFsCallbacks at tiny_gltf.cc:1225:16 in tiny_gltf.h
// tinygltf::TinyGLTF::SetURICallbacks at tiny_gltf.cc:1211:16 in tiny_gltf.h
// tinygltf::TinyGLTF::SetURICallbacks at tiny_gltf.cc:1211:16 in tiny_gltf.h
// tinygltf::IsDataURI at tiny_gltf.cc:1693:6 in tiny_gltf.h
// tinygltf::URIDecode at tiny_gltf.cc:842:6 in tiny_gltf.h
// tinygltf::DecodeDataURI at tiny_gltf.cc:1732:6 in tiny_gltf.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

#include "tiny_gltf.h"

static std::string dummy_file_path = "./dummy_file";

static void writeDummyFile(const uint8_t* data, size_t size) {
    std::ofstream file(dummy_file_path, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
    }
}

static bool dummyFileExists(const std::string& filename, void* user_data) {
    return true;
}

static std::string dummyExpandFilePath(const std::string& path, void* user_data) {
    return path;
}

static bool dummyReadWholeFile(std::vector<unsigned char>* out,
                               std::string* err,
                               const std::string& filename,
                               void* user_data) {
    out->push_back('t');
    out->push_back('e');
    out->push_back('s');
    out->push_back('t');
    return true;
}

static bool dummyWriteWholeFile(std::string* err,
                                const std::string& filename,
                                const std::vector<unsigned char>& contents,
                                void* user_data) {
    return true;
}

static bool dummyGetFileSizeInBytes(size_t* out,
                                    std::string* err,
                                    const std::string& filename,
                                    void* user_data) {
    *out = 4;
    return true;
}

static bool dummyURIEncode(const std::string& in_uri,
                           const std::string& base,
                           std::string* out_uri,
                           void* user_data) {
    *out_uri = in_uri;
    return true;
}

static bool dummyURIDecode(const std::string& in_uri,
                           std::string* out_uri,
                           void* user_data) {
    *out_uri = in_uri;
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create input string from fuzzer data
    std::string input_str(reinterpret_cast<const char*>(Data), Size);

    // Test 1: URIDecode
    {
        std::string out_uri;
        bool result = tinygltf::URIDecode(input_str, &out_uri, nullptr);
        (void)result;
    }

    // Test 2: DecodeDataURI
    {
        std::vector<unsigned char> out_data;
        std::string mime_type;
        // Use various combinations of parameters
        bool result1 = tinygltf::DecodeDataURI(&out_data, mime_type, input_str, 0, false);
        (void)result1;
        
        bool result2 = tinygltf::DecodeDataURI(&out_data, mime_type, input_str, Size, true);
        (void)result2;
        
        bool result3 = tinygltf::DecodeDataURI(&out_data, mime_type, input_str, Size/2, false);
        (void)result3;
    }

    // Test 3: WriteImageData
    {
        tinygltf::Image image;
        image.name = "test_image";
        image.width = static_cast<int>(Size % 1000);
        image.image.assign(Data, Data + Size);
        image.as_is = (Size % 2 == 0);
        
        std::string basepath = "./";
        std::string filename = "test.png";
        std::string out_uri;
        
        // Create dummy filesystem callbacks
        tinygltf::FsCallbacks fs_callbacks;
        fs_callbacks.FileExists = dummyFileExists;
        fs_callbacks.ExpandFilePath = dummyExpandFilePath;
        fs_callbacks.ReadWholeFile = dummyReadWholeFile;
        fs_callbacks.WriteWholeFile = dummyWriteWholeFile;
        fs_callbacks.GetFileSizeInBytes = dummyGetFileSizeInBytes;
        fs_callbacks.user_data = nullptr;
        
        // Create dummy URI callbacks
        tinygltf::URICallbacks uri_callbacks;
        uri_callbacks.encode = dummyURIEncode;
        uri_callbacks.decode = dummyURIDecode;
        uri_callbacks.user_data = nullptr;
        
        // Test with embedImages = true
        bool result1 = tinygltf::WriteImageData(&basepath, &filename, &image, true, 
                                               &fs_callbacks, &uri_callbacks, &out_uri, nullptr);
        (void)result1;
        
        // Test with embedImages = false
        writeDummyFile(Data, Size);
        bool result2 = tinygltf::WriteImageData(&basepath, &filename, &image, false,
                                               &fs_callbacks, &uri_callbacks, &out_uri, nullptr);
        (void)result2;
        
        // Test with nullptr parameters
        bool result3 = tinygltf::WriteImageData(nullptr, nullptr, &image, true,
                                               &fs_callbacks, &uri_callbacks, &out_uri, nullptr);
        (void)result3;
    }

    // Test 4: TinyGLTF::SetFsCallbacks
    {
        tinygltf::TinyGLTF loader;
        std::string err;
        
        tinygltf::FsCallbacks fs_callbacks;
        fs_callbacks.FileExists = dummyFileExists;
        fs_callbacks.ExpandFilePath = dummyExpandFilePath;
        fs_callbacks.ReadWholeFile = dummyReadWholeFile;
        fs_callbacks.WriteWholeFile = dummyWriteWholeFile;
        fs_callbacks.GetFileSizeInBytes = dummyGetFileSizeInBytes;
        fs_callbacks.user_data = nullptr;
        
        bool result = loader.SetFsCallbacks(fs_callbacks, &err);
        (void)result;
        
        // Test with nullptr callbacks
        tinygltf::FsCallbacks null_fs_callbacks;
        null_fs_callbacks.FileExists = nullptr;
        null_fs_callbacks.ExpandFilePath = nullptr;
        null_fs_callbacks.ReadWholeFile = nullptr;
        null_fs_callbacks.WriteWholeFile = nullptr;
        null_fs_callbacks.GetFileSizeInBytes = nullptr;
        null_fs_callbacks.user_data = nullptr;
        
        bool result2 = loader.SetFsCallbacks(null_fs_callbacks, &err);
        (void)result2;
    }

    // Test 5: TinyGLTF::SetURICallbacks
    {
        tinygltf::TinyGLTF loader;
        std::string err;
        
        tinygltf::URICallbacks uri_callbacks;
        uri_callbacks.encode = dummyURIEncode;
        uri_callbacks.decode = dummyURIDecode;
        uri_callbacks.user_data = nullptr;
        
        bool result = loader.SetURICallbacks(uri_callbacks, &err);
        (void)result;
        
        // Test with nullptr decode callback
        tinygltf::URICallbacks null_uri_callbacks;
        null_uri_callbacks.encode = dummyURIEncode;
        null_uri_callbacks.decode = nullptr;
        null_uri_callbacks.user_data = nullptr;
        
        bool result2 = loader.SetURICallbacks(null_uri_callbacks, &err);
        (void)result2;
    }

    // Test 6: IsDataURI
    {
        bool result = tinygltf::IsDataURI(input_str);
        (void)result;
    }

    return 0;
}