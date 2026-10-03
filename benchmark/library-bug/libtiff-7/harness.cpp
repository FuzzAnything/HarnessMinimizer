/*
 * harness_012.cpp - PixarLog Codec DECODE Deep Fuzzer for libtiff
 *
 * Targets deeply uncovered PixarLog-specific DECODE code paths in tif_pixarlog.c:
 *   - PixarLogSetupDecode: buffer allocation, data format guessing, inflateInit
 *   - PixarLogPreDecode: inflateReset, raw data setup
 *   - PixarLogDecode: zlib inflate, byte swapping, horizontal accumulate conversions
 *   - All 6 PIXARLOGDATAFMT values: FLOAT, 16BIT, 12BITPICIO, 11BITLOG, 8BIT, 8BITABGR
 *   - PixarLogGuessDataFmt auto-detection for various bitspersample/sampleformat combos
 *   - ABGR stride expansion path (stride==3, 4 bytes/pixel output)
 *   - Error handling: corrupted zlib data, truncated strips, invalid headers
 *   - TIFFReadRGBAImageOriented for RGBA decode path
 *   - Strip-based and tile-based layouts
 *   - Direct decode of arbitrary fuzz data as PixarLog-compressed TIFF
 *
 * Differentiation from existing harnesses:
 *   - harness_003 does generic codec roundtrip (basic PixarLog read)
 *   - This harness deeply exercises ALL PixarLog-specific decode parameters
 *   - Tests each PIXARLOGDATAFMT explicitly via TIFFSetField
 *   - Tests auto-detection path (PIXARLOGDATAFMT_UNKNOWN) with varied bit depths
 *   - Exercises float-to-integer conversion paths unique to PixarLog
 *   - Focuses on DECODE path (encode path has known allocation bug)
 *   - Tests corrupted/truncated PixarLog data for error recovery paths
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include <tiffio.h>

/* ------------------------------------------------------------------ */
/* In-memory I/O context for read mode                                */
/* ------------------------------------------------------------------ */

struct MemTIFFContext {
    const uint8_t *data;
    size_t size;
    size_t pos;
};

static tmsize_t mem_read(thandle_t handle, void *buf, tmsize_t nbytes) {
    MemTIFFContext *ctx = (MemTIFFContext *)handle;
    if (ctx->pos >= ctx->size) return 0;
    tmsize_t avail = (tmsize_t)(ctx->size - ctx->pos);
    if (nbytes > avail) nbytes = avail;
    memcpy(buf, ctx->data + ctx->pos, (size_t)nbytes);
    ctx->pos += (size_t)nbytes;
    return nbytes;
}

static tmsize_t mem_write_ro(thandle_t handle, void *buf, tmsize_t nbytes) {
    (void)handle; (void)buf; (void)nbytes;
    return nbytes;
}

static toff_t mem_seek(thandle_t handle, toff_t offset, int whence) {
    MemTIFFContext *ctx = (MemTIFFContext *)handle;
    size_t newpos;
    switch (whence) {
        case SEEK_SET: newpos = (size_t)offset; break;
        case SEEK_CUR: newpos = ctx->pos + (size_t)offset; break;
        case SEEK_END: newpos = ctx->size + (size_t)offset; break;
        default: return (toff_t)(-1);
    }
    if (newpos > ctx->size) newpos = ctx->size;
    ctx->pos = newpos;
    return (toff_t)ctx->pos;
}

static int mem_close(thandle_t handle) { (void)handle; return 0; }

static toff_t mem_size(thandle_t handle) {
    MemTIFFContext *ctx = (MemTIFFContext *)handle;
    return (toff_t)ctx->size;
}

static int mem_map(thandle_t handle, void **base, toff_t *psize) {
    (void)handle; (void)base; (void)psize;
    return 0;
}

static void mem_unmap(thandle_t handle, void *base, toff_t size) {
    (void)handle; (void)base; (void)size;
}

/* ------------------------------------------------------------------ */
/* In-memory I/O context for write mode (growable buffer)             */
/* ------------------------------------------------------------------ */

struct WriteMemIO {
    std::vector<uint8_t> buf;
    toff_t offset = 0;
};

static tmsize_t wmem_read(thandle_t handle, void *buf, tmsize_t size) {
    WriteMemIO *io = (WriteMemIO *)handle;
    if (io->offset >= (toff_t)io->buf.size()) return 0;
    tmsize_t avail = (tmsize_t)(io->buf.size() - io->offset);
    tmsize_t to_read = (size < avail) ? size : avail;
    memcpy(buf, io->buf.data() + io->offset, to_read);
    io->offset += to_read;
    return to_read;
}

static tmsize_t wmem_write(thandle_t handle, void *buf, tmsize_t size) {
    WriteMemIO *io = (WriteMemIO *)handle;
    if (io->offset + size > io->buf.size())
        io->buf.resize(io->offset + size);
    memcpy(io->buf.data() + io->offset, buf, size);
    io->offset += size;
    return size;
}

static toff_t wmem_seek(thandle_t handle, toff_t offset, int whence) {
    WriteMemIO *io = (WriteMemIO *)handle;
    toff_t newpos;
    switch (whence) {
        case SEEK_SET: newpos = offset; break;
        case SEEK_CUR: newpos = io->offset + offset; break;
        case SEEK_END: newpos = (toff_t)io->buf.size() + offset; break;
        default: return (toff_t)(-1);
    }
    io->offset = newpos;
    return newpos;
}

static int wmem_close(thandle_t handle) { (void)handle; return 0; }

static toff_t wmem_size(thandle_t handle) {
    WriteMemIO *io = (WriteMemIO *)handle;
    return (toff_t)io->buf.size();
}

static int wmem_map(thandle_t handle, void **base, toff_t *psize) {
    (void)handle; (void)base; (void)psize;
    return 0;
}

static void wmem_unmap(thandle_t handle, void *base, toff_t size) {
    (void)handle; (void)base; (void)size;
}

/* ------------------------------------------------------------------ */
/* Error / warning suppression                                        */
/* ------------------------------------------------------------------ */

static void silent_handler(const char *module, const char *fmt, va_list ap) {
    (void)module; (void)fmt; (void)ap;
}

/* ------------------------------------------------------------------ */
/* Constants and helpers                                              */
/* ------------------------------------------------------------------ */

static const uint64_t MAX_SIZE = 50 * 1024 * 1024; /* 50 MB */

#define TIFF_SAFE_MULTIPLY(t, v, m)                                           \
    ((((t)(m) != (t)0) && (((t)(((v) * (m)) / (m))) == (t)(v)))               \
         ? (t)((v) * (m))                                                     \
         : (t)0)

/* ------------------------------------------------------------------ */
/* PixarLog image configuration table                                 */
/* Each config exercises a different PixarLogGuessDataFmt path        */
/* ------------------------------------------------------------------ */

struct PixarLogConfig {
    uint16_t spp;          /* samples per pixel */
    uint16_t bps;          /* bits per sample */
    uint16_t photometric;  /* photometric interpretation */
    uint16_t sampleformat; /* sample format */
    uint16_t planarconfig; /* planar configuration */
    const char *name;
};

static const PixarLogConfig kPixarLogConfigs[] = {
    /* 32-bit float grayscale - guesses PIXARLOGDATAFMT_FLOAT */
    { 1, 32, PHOTOMETRIC_MINISBLACK, SAMPLEFORMAT_IEEEFP, PLANARCONFIG_CONTIG, "gray32f" },
    /* 32-bit float RGB - guesses PIXARLOGDATAFMT_FLOAT */
    { 3, 32, PHOTOMETRIC_RGB, SAMPLEFORMAT_IEEEFP, PLANARCONFIG_CONTIG, "rgb32f" },
    /* 16-bit grayscale - guesses PIXARLOGDATAFMT_16BIT */
    { 1, 16, PHOTOMETRIC_MINISBLACK, SAMPLEFORMAT_UINT, PLANARCONFIG_CONTIG, "gray16" },
    /* 16-bit RGB - guesses PIXARLOGDATAFMT_16BIT */
    { 3, 16, PHOTOMETRIC_RGB, SAMPLEFORMAT_UINT, PLANARCONFIG_CONTIG, "rgb16" },
    /* 8-bit grayscale - guesses PIXARLOGDATAFMT_8BIT */
    { 1, 8, PHOTOMETRIC_MINISBLACK, SAMPLEFORMAT_UINT, PLANARCONFIG_CONTIG, "gray8" },
    /* 8-bit RGB - guesses PIXARLOGDATAFMT_8BIT (also good for 8BITABGR) */
    { 3, 8, PHOTOMETRIC_RGB, SAMPLEFORMAT_UINT, PLANARCONFIG_CONTIG, "rgb8" },
    /* 8-bit RGBA - guesses PIXARLOGDATAFMT_8BIT (also good for 8BITABGR) */
    { 4, 8, PHOTOMETRIC_RGB, SAMPLEFORMAT_UINT, PLANARCONFIG_CONTIG, "rgba8" },
    /* 12-bit INT - guesses PIXARLOGDATAFMT_12BITPICIO */
    { 1, 12, PHOTOMETRIC_MINISBLACK, SAMPLEFORMAT_INT, PLANARCONFIG_CONTIG, "gray12int" },
    /* 11-bit UINT - guesses PIXARLOGDATAFMT_11BITLOG */
    { 1, 11, PHOTOMETRIC_MINISBLACK, SAMPLEFORMAT_UINT, PLANARCONFIG_CONTIG, "gray11" },
    /* 16-bit VOID - guesses PIXARLOGDATAFMT_16BIT */
    { 1, 16, PHOTOMETRIC_MINISBLACK, SAMPLEFORMAT_VOID, PLANARCONFIG_CONTIG, "gray16void" },
    /* Planar config SEPARATE with 3 samples */
    { 3, 8, PHOTOMETRIC_RGB, SAMPLEFORMAT_UINT, PLANARCONFIG_SEPARATE, "rgb8_separate" },
    /* 32-bit float RGBA */
    { 4, 32, PHOTOMETRIC_RGB, SAMPLEFORMAT_IEEEFP, PLANARCONFIG_CONTIG, "rgba32f" },
};
static const int kNumConfigs = sizeof(kPixarLogConfigs) / sizeof(kPixarLogConfigs[0]);

/* All PIXARLOGDATAFMT values to test explicitly */
static const int kDataFmts[] = {
    PIXARLOGDATAFMT_8BIT,
    PIXARLOGDATAFMT_8BITABGR,
    PIXARLOGDATAFMT_11BITLOG,
    PIXARLOGDATAFMT_12BITPICIO,
    PIXARLOGDATAFMT_16BIT,
    PIXARLOGDATAFMT_FLOAT,
};
static const int kNumDataFmts = sizeof(kDataFmts) / sizeof(kDataFmts[0]);

/* ------------------------------------------------------------------ */
/* Fill pixel buffer with fuzz data                                    */
/* ------------------------------------------------------------------ */

static void fill_pixel_data(uint8_t *buf, size_t buf_size,
                            FuzzedDataProvider &fdp) {
    size_t consume_bytes = fdp.ConsumeIntegralInRange<size_t>(
        0, (buf_size < 4096) ? buf_size : 4096);
    std::vector<uint8_t> raw = fdp.ConsumeBytes<uint8_t>(consume_bytes);
    if (raw.empty()) raw.resize(1, 0);

    for (size_t i = 0; i < buf_size; i++) {
        buf[i] = raw[i % raw.size()];
    }
}

/* ------------------------------------------------------------------ */
/* Write a PixarLog-compressed TIFF to memory                          */
/* Keep dimensions small to avoid the known encode allocation bug     */
/* ------------------------------------------------------------------ */

static bool write_pixarlog_tiff(WriteMemIO &io, const PixarLogConfig &cfg,
                                uint32_t width, uint32_t height,
                                bool use_tiles, uint32_t tile_w, uint32_t tile_h,
                                int quality, FuzzedDataProvider &fdp) {
    io.buf.clear();
    io.offset = 0;
    io.buf.reserve(8192);

    TIFF *tif = TIFFClientOpen("pixarlog_write", "w", (thandle_t)&io,
                               wmem_read, wmem_write, wmem_seek,
                               wmem_close, wmem_size,
                               wmem_map, wmem_unmap);
    if (!tif) return false;

    TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height);
    TIFFSetField(tif, TIFFTAG_BITSPERSAMPLE, cfg.bps);
    TIFFSetField(tif, TIFFTAG_SAMPLESPERPIXEL, cfg.spp);
    TIFFSetField(tif, TIFFTAG_COMPRESSION, COMPRESSION_PIXARLOG);
    TIFFSetField(tif, TIFFTAG_PHOTOMETRIC, cfg.photometric);
    TIFFSetField(tif, TIFFTAG_PLANARCONFIG, cfg.planarconfig);
    TIFFSetField(tif, TIFFTAG_SAMPLEFORMAT, cfg.sampleformat);
    TIFFSetField(tif, TIFFTAG_ORIENTATION, ORIENTATION_TOPLEFT);

    /* PixarLog-specific: quality (affects deflate compression level) */
    if (quality >= 0) {
        TIFFSetField(tif, TIFFTAG_PIXARLOGQUALITY, quality);
    }

    /* Configure strip or tile layout */
    if (use_tiles) {
        TIFFSetField(tif, TIFFTAG_TILEWIDTH, tile_w);
        TIFFSetField(tif, TIFFTAG_TILELENGTH, tile_h);
    } else {
        uint32_t rps = TIFFDefaultStripSize(tif, 0);
        if (rps == 0 || rps > height) rps = height;
        TIFFSetField(tif, TIFFTAG_ROWSPERSTRIP, rps);
    }

    /* Compute buffer sizes and write data */
    if (use_tiles) {
        tmsize_t tile_size = TIFFTileSize(tif);
        if (tile_size <= 0) {
            TIFFClose(tif);
            return false;
        }

        uint32_t tw, th;
        TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tw);
        TIFFGetField(tif, TIFFTAG_TILELENGTH, &th);
        uint32_t tiles_across = (width + tw - 1) / tw;
        uint32_t tiles_down = (height + th - 1) / th;
        uint32_t num_tiles = tiles_across * tiles_down;

        std::vector<uint8_t> tile_buf(tile_size, 0);
        for (uint32_t t = 0; t < num_tiles; t++) {
            fill_pixel_data(tile_buf.data(), tile_size, fdp);
            TIFFWriteEncodedTile(tif, t, tile_buf.data(), tile_size);
        }
    } else {
        uint32_t rps;
        TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rps);
        if (rps == 0) rps = height;

        tmsize_t strip_size = TIFFStripSize(tif);
        if (strip_size <= 0) {
            tmsize_t scanline_size = TIFFScanlineSize(tif);
            if (scanline_size <= 0) {
                TIFFClose(tif);
                return false;
            }
            strip_size = scanline_size * (tmsize_t)rps;
        }

        uint32_t num_strips = (height + rps - 1) / rps;

        std::vector<uint8_t> strip_buf(strip_size, 0);
        for (uint32_t s = 0; s < num_strips; s++) {
            fill_pixel_data(strip_buf.data(), strip_size, fdp);
            TIFFWriteEncodedStrip(tif, s, strip_buf.data(), strip_size);
        }
    }

    TIFFWriteDirectory(tif);
    TIFFClose(tif);
    return true;
}

/* ------------------------------------------------------------------ */
/* Read back a PixarLog-compressed TIFF from memory                    */
/* Tests each PIXARLOGDATAFMT value to exercise all decode paths      */
/* ------------------------------------------------------------------ */

static void read_pixarlog_tiff_all_fmts(const WriteMemIO &io) {
    if (io.buf.empty()) return;

    /* Test each PIXARLOGDATAFMT value */
    for (int fi = 0; fi < kNumDataFmts; fi++) {
        MemTIFFContext rctx;
        rctx.data = io.buf.data();
        rctx.size = io.buf.size();
        rctx.pos = 0;

        TIFF *tif = TIFFClientOpen("pixarlog_read", "r", (thandle_t)&rctx,
                                   mem_read, mem_write_ro, mem_seek,
                                   mem_close, mem_size,
                                   mem_map, mem_unmap);
        if (!tif) continue;

        /* Set the specific data format to exercise different decode paths */
        TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, kDataFmts[fi]);

        do {
            uint32_t w = 0, h = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
            if (w == 0 || h == 0) continue;

            uint64_t total_pixels = TIFF_SAFE_MULTIPLY(uint64_t, w, h);
            if (total_pixels == 0 || total_pixels > MAX_SIZE / sizeof(uint32_t))
                continue;

            bool is_tiled = TIFFIsTiled(tif);

            /* Strip-based reading */
            if (!is_tiled) {
                /* Scanline reading */
                tmsize_t scanline_size = TIFFScanlineSize(tif);
                if (scanline_size > 0 && (uint64_t)scanline_size <= MAX_SIZE) {
                    void *buf = _TIFFmalloc(scanline_size);
                    if (buf) {
                        uint32_t max_rows = h > 32 ? 32 : h;
                        for (uint32_t row = 0; row < max_rows; row++) {
                            if (TIFFReadScanline(tif, buf, row, 0) < 0)
                                break;
                        }
                        _TIFFfree(buf);
                    }
                }

                /* Strip reading */
                uint32_t num_strips = TIFFNumberOfStrips(tif);
                tmsize_t strip_size = TIFFStripSize(tif);
                if (strip_size > 0 &&
                    (uint64_t)strip_size <= MAX_SIZE &&
                    num_strips > 0 && num_strips < 10000) {
                    void *sbuf = _TIFFmalloc(strip_size);
                    if (sbuf) {
                        for (uint32_t s = 0; s < num_strips && s < 32; s++) {
                            TIFFReadEncodedStrip(tif, s, sbuf, strip_size);
                        }
                        _TIFFfree(sbuf);
                    }
                }
            }

            /* Tile-based reading */
            if (is_tiled) {
                uint32_t num_tiles = TIFFNumberOfTiles(tif);
                tmsize_t tile_size = TIFFTileSize(tif);
                if (tile_size > 0 &&
                    (uint64_t)tile_size <= MAX_SIZE &&
                    num_tiles > 0 && num_tiles < 10000) {
                    void *tbuf = _TIFFmalloc(tile_size);
                    if (tbuf) {
                        for (uint32_t t = 0; t < num_tiles && t < 32; t++) {
                            TIFFReadEncodedTile(tif, t, tbuf, tile_size);
                        }
                        _TIFFfree(tbuf);
                    }
                }
            }
        } while (TIFFReadDirectory(tif));

        TIFFClose(tif);
    }

    /* Also test with auto-detection (don't set PIXARLOGDATAFMT) */
    {
        MemTIFFContext rctx;
        rctx.data = io.buf.data();
        rctx.size = io.buf.size();
        rctx.pos = 0;

        TIFF *tif = TIFFClientOpen("pixarlog_auto", "r", (thandle_t)&rctx,
                                   mem_read, mem_write_ro, mem_seek,
                                   mem_close, mem_size,
                                   mem_map, mem_unmap);
        if (!tif) return;

        /* Don't set PIXARLOGDATAFMT - let PixarLogGuessDataFmt auto-detect */
        do {
            uint32_t w = 0, h = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
            if (w == 0 || h == 0) continue;

            uint64_t total_pixels = TIFF_SAFE_MULTIPLY(uint64_t, w, h);
            if (total_pixels == 0 || total_pixels > MAX_SIZE / sizeof(uint32_t))
                continue;

            bool is_tiled = TIFFIsTiled(tif);

            if (!is_tiled) {
                uint32_t num_strips = TIFFNumberOfStrips(tif);
                tmsize_t strip_size = TIFFStripSize(tif);
                if (strip_size > 0 &&
                    (uint64_t)strip_size <= MAX_SIZE &&
                    num_strips > 0 && num_strips < 10000) {
                    void *sbuf = _TIFFmalloc(strip_size);
                    if (sbuf) {
                        for (uint32_t s = 0; s < num_strips && s < 32; s++) {
                            TIFFReadEncodedStrip(tif, s, sbuf, strip_size);
                        }
                        _TIFFfree(sbuf);
                    }
                }
            }

            if (is_tiled) {
                uint32_t num_tiles = TIFFNumberOfTiles(tif);
                tmsize_t tile_size = TIFFTileSize(tif);
                if (tile_size > 0 &&
                    (uint64_t)tile_size <= MAX_SIZE &&
                    num_tiles > 0 && num_tiles < 10000) {
                    void *tbuf = _TIFFmalloc(tile_size);
                    if (tbuf) {
                        for (uint32_t t = 0; t < num_tiles && t < 32; t++) {
                            TIFFReadEncodedTile(tif, t, tbuf, tile_size);
                        }
                        _TIFFfree(tbuf);
                    }
                }
            }
        } while (TIFFReadDirectory(tif));

        TIFFClose(tif);
    }

    /* Test RGBA decode path */
    {
        MemTIFFContext rctx;
        rctx.data = io.buf.data();
        rctx.size = io.buf.size();
        rctx.pos = 0;

        TIFF *tif = TIFFClientOpen("pixarlog_rgba", "r", (thandle_t)&rctx,
                                   mem_read, mem_write_ro, mem_seek,
                                   mem_close, mem_size,
                                   mem_map, mem_unmap);
        if (!tif) return;

        do {
            uint32_t w = 0, h = 0;
            TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
            if (w == 0 || h == 0) continue;

            uint64_t total_pixels = TIFF_SAFE_MULTIPLY(uint64_t, w, h);
            if (total_pixels == 0 || total_pixels > 65536)
                continue;

            uint32_t *raster = (uint32_t *)_TIFFmalloc(
                (tmsize_t)(w * h * sizeof(uint32_t)));
            if (raster) {
                TIFFReadRGBAImageOriented(tif, w, h, raster,
                                          ORIENTATION_TOPLEFT, 0);
                _TIFFfree(raster);
            }
        } while (TIFFReadDirectory(tif));

        TIFFClose(tif);
    }
}

/* ------------------------------------------------------------------ */
/* Read back with a single specific PIXARLOGDATAFMT                    */
/* ------------------------------------------------------------------ */

static void read_pixarlog_tiff_single_fmt(const WriteMemIO &io, int datafmt) {
    if (io.buf.empty()) return;

    MemTIFFContext rctx;
    rctx.data = io.buf.data();
    rctx.size = io.buf.size();
    rctx.pos = 0;

    TIFF *tif = TIFFClientOpen("pixarlog_single", "r", (thandle_t)&rctx,
                               mem_read, mem_write_ro, mem_seek,
                               mem_close, mem_size,
                               mem_map, mem_unmap);
    if (!tif) return;

    TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, datafmt);

    do {
        uint32_t w = 0, h = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
        if (w == 0 || h == 0) continue;

        uint64_t total_pixels = TIFF_SAFE_MULTIPLY(uint64_t, w, h);
        if (total_pixels == 0 || total_pixels > MAX_SIZE / sizeof(uint32_t))
            continue;

        bool is_tiled = TIFFIsTiled(tif);

        if (!is_tiled) {
            uint32_t num_strips = TIFFNumberOfStrips(tif);
            tmsize_t strip_size = TIFFStripSize(tif);
            if (strip_size > 0 &&
                (uint64_t)strip_size <= MAX_SIZE &&
                num_strips > 0 && num_strips < 10000) {
                void *sbuf = _TIFFmalloc(strip_size);
                if (sbuf) {
                    for (uint32_t s = 0; s < num_strips && s < 64; s++) {
                        TIFFReadEncodedStrip(tif, s, sbuf, strip_size);
                    }
                    _TIFFfree(sbuf);
                }
            }
        }

        if (is_tiled) {
            uint32_t num_tiles = TIFFNumberOfTiles(tif);
            tmsize_t tile_size = TIFFTileSize(tif);
            if (tile_size > 0 &&
                (uint64_t)tile_size <= MAX_SIZE &&
                num_tiles > 0 && num_tiles < 10000) {
                void *tbuf = _TIFFmalloc(tile_size);
                if (tbuf) {
                    for (uint32_t t = 0; t < num_tiles && t < 64; t++) {
                        TIFFReadEncodedTile(tif, t, tbuf, tile_size);
                    }
                    _TIFFfree(tbuf);
                }
            }
        }
    } while (TIFFReadDirectory(tif));

    TIFFClose(tif);
}

/* ------------------------------------------------------------------ */
/* Direct decode of arbitrary fuzz data as a TIFF file                 */
/* (exercises PixarLog decode error paths with corrupted data)        */
/* ------------------------------------------------------------------ */

static void direct_decode_fuzz_data(const uint8_t *data, size_t size) {
    if (size < 16) return;

    MemTIFFContext rctx;
    rctx.data = data;
    rctx.size = size;
    rctx.pos = 0;

    TIFF *tif = TIFFClientOpen("pixarlog_fuzz_decode", "r", (thandle_t)&rctx,
                               mem_read, mem_write_ro, mem_seek,
                               mem_close, mem_size,
                               mem_map, mem_unmap);
    if (!tif) return;

    do {
        uint32_t w = 0, h = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
        if (w == 0 || h == 0 || w > 4096 || h > 4096) continue;

        uint16_t compression = 0;
        TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);

        /* Only proceed if this is PixarLog-compressed */
        if (compression != COMPRESSION_PIXARLOG) continue;

        /* Try setting different data formats to exercise error paths */
        int try_fmts[] = { PIXARLOGDATAFMT_FLOAT, PIXARLOGDATAFMT_16BIT,
                           PIXARLOGDATAFMT_8BIT, PIXARLOGDATAFMT_8BITABGR,
                           PIXARLOGDATAFMT_11BITLOG, PIXARLOGDATAFMT_12BITPICIO };

        for (int fi = 0; fi < 6; fi++) {
            TIFFSetField(tif, TIFFTAG_PIXARLOGDATAFMT, try_fmts[fi]);

            bool is_tiled = TIFFIsTiled(tif);

            if (is_tiled) {
                tmsize_t tile_size = TIFFTileSize(tif);
                if (tile_size > 0 && tile_size < 10 * 1024 * 1024) {
                    uint32_t tw = 0, th = 0;
                    TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tw);
                    TIFFGetField(tif, TIFFTAG_TILELENGTH, &th);
                    if (tw > 0 && th > 0) {
                        uint32_t tiles_across = (w + tw - 1) / tw;
                        uint32_t tiles_down = (h + th - 1) / th;
                        uint32_t num_tiles = tiles_across * tiles_down;
                        if (num_tiles > 0 && num_tiles < 10000) {
                            void *tbuf = _TIFFmalloc(tile_size);
                            if (tbuf) {
                                for (uint32_t t = 0; t < num_tiles && t < 16; t++) {
                                    TIFFReadEncodedTile(tif, t, tbuf, tile_size);
                                }
                                _TIFFfree(tbuf);
                            }
                        }
                    }
                }
            } else {
                uint32_t num_strips = TIFFNumberOfStrips(tif);
                tmsize_t strip_size = TIFFStripSize(tif);
                if (strip_size > 0 && strip_size < 10 * 1024 * 1024 &&
                    num_strips > 0 && num_strips < 10000) {
                    void *sbuf = _TIFFmalloc(strip_size);
                    if (sbuf) {
                        for (uint32_t s = 0; s < num_strips && s < 16; s++) {
                            TIFFReadEncodedStrip(tif, s, sbuf, strip_size);
                        }
                        _TIFFfree(sbuf);
                    }
                }

                /* Also try scanline reading for error path coverage */
                tmsize_t scanline_size = TIFFScanlineSize(tif);
                if (scanline_size > 0 && scanline_size < 1024 * 1024) {
                    void *sbuf = _TIFFmalloc(scanline_size);
                    if (sbuf) {
                        uint32_t max_rows = h > 16 ? 16 : h;
                        for (uint32_t row = 0; row < max_rows; row++) {
                            if (TIFFReadScanline(tif, sbuf, row, 0) < 0)
                                break;
                        }
                        _TIFFfree(sbuf);
                    }
                }
            }
        }

        /* Also try RGBA decode for error path coverage */
        if (w * h <= 65536) {
            uint32_t *raster = (uint32_t *)_TIFFmalloc(
                (tmsize_t)(w * h * sizeof(uint32_t)));
            if (raster) {
                TIFFReadRGBAImageOriented(tif, w, h, raster,
                                          ORIENTATION_TOPLEFT, 0);
                _TIFFfree(raster);
            }
        }

    } while (TIFFReadDirectory(tif));

    TIFFClose(tif);
}

/* ------------------------------------------------------------------ */
/* Direct decode with auto-detection (no PIXARLOGDATAFMT set)         */
/* Exercises PixarLogGuessDataFmt with arbitrary TIFF headers          */
/* ------------------------------------------------------------------ */

static void direct_decode_auto_detect(const uint8_t *data, size_t size) {
    if (size < 16) return;

    MemTIFFContext rctx;
    rctx.data = data;
    rctx.size = size;
    rctx.pos = 0;

    TIFF *tif = TIFFClientOpen("pixarlog_auto_decode", "r", (thandle_t)&rctx,
                               mem_read, mem_write_ro, mem_seek,
                               mem_close, mem_size,
                               mem_map, mem_unmap);
    if (!tif) return;

    do {
        uint32_t w = 0, h = 0;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &w);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &h);
        if (w == 0 || h == 0 || w > 4096 || h > 4096) continue;

        uint16_t compression = 0;
        TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);
        if (compression != COMPRESSION_PIXARLOG) continue;

        /* Don't set PIXARLOGDATAFMT - let auto-detection work */
        bool is_tiled = TIFFIsTiled(tif);

        if (is_tiled) {
            tmsize_t tile_size = TIFFTileSize(tif);
            if (tile_size > 0 && tile_size < 10 * 1024 * 1024) {
                uint32_t num_tiles = TIFFNumberOfTiles(tif);
                if (num_tiles > 0 && num_tiles < 10000) {
                    void *tbuf = _TIFFmalloc(tile_size);
                    if (tbuf) {
                        for (uint32_t t = 0; t < num_tiles && t < 16; t++) {
                            TIFFReadEncodedTile(tif, t, tbuf, tile_size);
                        }
                        _TIFFfree(tbuf);
                    }
                }
            }
        } else {
            uint32_t num_strips = TIFFNumberOfStrips(tif);
            tmsize_t strip_size = TIFFStripSize(tif);
            if (strip_size > 0 && strip_size < 10 * 1024 * 1024 &&
                num_strips > 0 && num_strips < 10000) {
                void *sbuf = _TIFFmalloc(strip_size);
                if (sbuf) {
                    for (uint32_t s = 0; s < num_strips && s < 16; s++) {
                        TIFFReadEncodedStrip(tif, s, sbuf, strip_size);
                    }
                    _TIFFfree(sbuf);
                }
            }
        }
    } while (TIFFReadDirectory(tif));

    TIFFClose(tif);
}

/* ------------------------------------------------------------------ */
/* Main fuzzer entry point                                            */
/* ------------------------------------------------------------------ */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;

    /* Suppress TIFF error/warning output */
    TIFFSetErrorHandler(silent_handler);
    TIFFSetWarningHandler(silent_handler);

    FuzzedDataProvider fdp(data, size);

    /* Choose test mode:
     * 0 = Roundtrip (strip) - write PixarLog TIFF, read back with all data formats
     * 1 = Roundtrip (tile) - write PixarLog TIFF, read back with all data formats
     * 2 = Roundtrip with single specific data format (deep test one path)
     * 3 = Direct decode of arbitrary fuzz data (corrupted data error paths)
     * 4 = Direct decode with auto-detection (PixarLogGuessDataFmt)
     * 5 = Roundtrip with quality variation
     */
    uint8_t mode = fdp.ConsumeIntegral<uint8_t>() % 6;

    if (mode == 3) {
        /* Direct decode of fuzz data as PixarLog TIFF - exercises decode
         * error paths with corrupted/invalid compressed data */
        std::vector<uint8_t> remaining = fdp.ConsumeRemainingBytes<uint8_t>();
        direct_decode_fuzz_data(remaining.data(), remaining.size());
        return 0;
    }

    if (mode == 4) {
        /* Direct decode with auto-detection */
        std::vector<uint8_t> remaining = fdp.ConsumeRemainingBytes<uint8_t>();
        direct_decode_auto_detect(remaining.data(), remaining.size());
        return 0;
    }

    /* Select configuration from table */
    int cfg_idx = fdp.ConsumeIntegralInRange<int>(0, kNumConfigs - 1);
    const PixarLogConfig &cfg = kPixarLogConfigs[cfg_idx];

    /* Image dimensions - keep small to avoid encode allocation bug */
    uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);
    uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(1, 32);

    /* PixarLog quality (deflate compression level, typically 1-9) */
    int quality = -1; /* -1 means don't set (use default) */
    if (mode == 5) {
        /* Test various quality levels */
        quality = fdp.ConsumeIntegralInRange<int>(1, 9);
    }

    bool use_tiles = (mode == 1);

    uint32_t tile_w = 16, tile_h = 16;
    if (use_tiles) {
        tile_w = fdp.ConsumeIntegralInRange<uint32_t>(8, 32);
        tile_h = fdp.ConsumeIntegralInRange<uint32_t>(8, 32);
        if (tile_w > width) tile_w = width;
        if (tile_h > height) tile_h = height;
    }

    /* Write PixarLog-compressed TIFF */
    WriteMemIO io;
    bool ok = write_pixarlog_tiff(io, cfg, width, height,
                                  use_tiles, tile_w, tile_h,
                                  quality, fdp);

    if (!ok) return 0;

    if (mode == 2) {
        /* Single data format deep test */
        int datafmt_idx = fdp.ConsumeIntegralInRange<int>(0, kNumDataFmts - 1);
        read_pixarlog_tiff_single_fmt(io, kDataFmts[datafmt_idx]);
    } else {
        /* Read back with all data formats + auto-detect + RGBA */
        read_pixarlog_tiff_all_fmts(io);
    }

    return 0;
}

