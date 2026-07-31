// poc.cc
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if(size<=0) return 0;

    // Open input tiff in memory
    std::istringstream s(std::string(data, data + size));
    TIFF* in_tif = TIFFStreamOpen("MemTIFF", &s);
    if (!in_tif) {
	return 0;
    }

    // Create variables for tile dimensions
    uint32_t tile_width = 0;
    uint32_t tile_height = 0;

    // Get tile dimensions
    TIFFDefaultTileSize(in_tif, &tile_width, &tile_height);

    // Complete the event using libtiff APIs
    uint32_t tile_size = TIFFVTileSize64(in_tif, tile_height);
    uint32_t num_tiles_x = (TIFFComputeTile(in_tif, TIFFGetField(in_tif, TIFFTAG_IMAGEWIDTH, &tile_width),
                                            0, 0, 0) + tile_width - 1) / tile_width;
    uint32_t num_tiles_y = (TIFFComputeTile(in_tif, 0, TIFFGetField(in_tif, TIFFTAG_IMAGELENGTH, &tile_height),
                                            0, 0) + tile_height - 1) / tile_height;
    for (uint32_t y = 0; y < num_tiles_y; y++) {
        for (uint32_t x = 0; x < num_tiles_x; x++) {
            uint32_t* tile_buffer = (uint32_t*)_TIFFrealloc(NULL, tile_size);
            if (!tile_buffer) {
                TIFFClose(in_tif);
	return 0;
            }
            if (TIFFReadRGBATileExt(in_tif, x, y, tile_buffer, 0) != 0) {
                // Process the tile buffer
                // ...
            }
            _TIFFfree(tile_buffer);
        }
    }

    // Clean up
    TIFFClose(in_tif);
	return 0;
}