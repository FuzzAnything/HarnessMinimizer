/* Fuzzing harness for libtiff targeting TIFF directory manipulation operations */
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>

#include <tiffio.h>
#include <tiffio.hxx>

/* Error handler to suppress libtiff error messages during fuzzing */
extern "C" void handle_error(const char* unused, const char* unused2, va_list unused3) {
    // Suppress error messages during fuzzing
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Minimum size check - need enough data for configuration and operations
    if (size < 64) {
        return 0;
    }

    // Set error handlers to suppress libtiff messages
    TIFFSetErrorHandler(handle_error);
    TIFFSetWarningHandler(handle_error);

    FuzzedDataProvider fdp(data, size);

    // Consume parameters for directory operations
    bool test_exif = fdp.ConsumeBool();
    bool test_gps = fdp.ConsumeBool();
    bool test_checkpoint = fdp.ConsumeBool();
    bool test_unlink = fdp.ConsumeBool();
    
    // Consume values for various tags
    std::string exif_value = fdp.ConsumeRandomLengthString(100);
    std::string gps_value = fdp.ConsumeRandomLengthString(50);
    double flash_energy = fdp.ConsumeFloatingPoint<double>();
    double focal_length = fdp.ConsumeFloatingPoint<double>();
    
    // Use remaining data as TIFF file content
    std::string tiff_data = fdp.ConsumeRemainingBytesAsString();
    
    // Create a temporary filename for TIFF operations
    char filename[] = "/tmp/tiff_fuzz_dir_XXXXXX.tif";
    int fd = mkstemps(filename, 4);
    if (fd < 0) {
        return 0;
    }
    
    // Write TIFF data to the temporary file
    if (write(fd, tiff_data.c_str(), tiff_data.size()) != (ssize_t)tiff_data.size()) {
        close(fd);
        unlink(filename);
        return 0;
    }
    
    close(fd);
    
    // Open TIFF file for reading and writing
    TIFF* tif = TIFFOpen(filename, "r+");
    if (!tif) {
        // If opening in r+ mode fails, try w+ mode for creating new file
        tif = TIFFOpen(filename, "w+");
        if (!tif) {
            unlink(filename);
            return 0;
        }
    }
    
    uint64_t exif_dir_offset = 0;
    uint64_t gps_dir_offset = 0;
    
    // Test EXIF directory operations if enabled
    if (test_exif) {
        // Create EXIF directory
        if (TIFFCreateEXIFDirectory(tif) == 0) {
            // Set some EXIF fields
            TIFFSetField(tif, EXIFTAG_SPECTRALSENSITIVITY, exif_value.c_str());
            TIFFSetField(tif, EXIFTAG_FLASHENERGY, flash_energy);
            TIFFSetField(tif, EXIFTAG_FOCALLENGTH, focal_length);
            
            // Write the custom directory and get its offset
            if (TIFFWriteCustomDirectory(tif, &exif_dir_offset)) {
                // Test checkpointing if enabled
                if (test_checkpoint) {
                    TIFFCheckpointDirectory(tif);
                }
            }
        }
    }
    
    // Test GPS directory operations if enabled
    if (test_gps) {
        // Create GPS directory
        if (TIFFCreateGPSDirectory(tif) == 0) {
            // Set some GPS fields
            TIFFSetField(tif, GPSTAG_VERSIONID, gps_value.c_str());
            TIFFSetField(tif, GPSTAG_LATITUDEREF, fdp.ConsumeBool() ? "N" : "S");
            TIFFSetField(tif, GPSTAG_LONGITUDEREF, fdp.ConsumeBool() ? "E" : "W");
            TIFFSetField(tif, GPSTAG_ALTITUDEREF, fdp.ConsumeIntegral<uint8_t>());
            
            // Write the custom directory and get its offset
            if (TIFFWriteCustomDirectory(tif, &gps_dir_offset)) {
                // Test checkpointing if enabled
                if (test_checkpoint) {
                    TIFFCheckpointDirectory(tif);
                }
            }
        }
    }
    
    // Go back to first directory to set pointer tags if needed
    TIFFSetDirectory(tif, 0);
    
    // Set EXIFIFD pointer if we created EXIF directory
    if (exif_dir_offset != 0) {
        TIFFSetField(tif, TIFFTAG_EXIFIFD, exif_dir_offset);
    }
    
    // Set SUBIFD pointer if we created GPS directory
    if (gps_dir_offset != 0) {
        uint64_t subifd_offsets[1] = {gps_dir_offset};
        TIFFSetField(tif, TIFFTAG_SUBIFD, 1, subifd_offsets);
    }
    
    // Test reading the directories back
    if (exif_dir_offset != 0) {
        TIFFReadEXIFDirectory(tif, exif_dir_offset);
    }
    
    if (gps_dir_offset != 0) {
        TIFFReadGPSDirectory(tif, gps_dir_offset);
    }
    
    // Test directory unlinking if enabled
    if (test_unlink) {
        // Get current directory count
        tdir_t dir_count = TIFFNumberOfDirectories(tif);
        
        // Try to unlink some directories (avoid unlinking directory 0)
        if (dir_count > 1) {
            for (tdir_t dir = 1; dir < std::min(dir_count, (tdir_t)3); dir++) {
                TIFFUnlinkDirectory(tif, dir);
            }
        }
    }
    
    // Force a checkpoint before closing if not already done
    if (test_checkpoint) {
        TIFFCheckpointDirectory(tif);
    }
    
    // Clean up
    TIFFClose(tif);
    unlink(filename);
    
    return 0;
}
