// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "compression_utils.h"

#include <iostream>
#include <sstream>
#include <array>
#include <vector>
#include <tuple>
#include <strings.h>
#include <string.h>
#include <zlib.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

using namespace std;

using DebugFunction = void(*)(const char *);

static const int max_debug_level = static_cast<int>(CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ASSERTION);

static const int max_retries = 3;
static const size_t default_brotli_buffer_size = 16384;
static const size_t brotli_decompression_probe_size = 64;

static void
defaultPrint(const char *debug_message)
{
    cerr << debug_message;
};

class ZlibDebugStream
{
public:
    ZlibDebugStream(const CompressionUtilsDebugLevel _debug_level) : debug_level(_debug_level) {}

    ~ZlibDebugStream()
    {
        ZlibDebugStream::debug_funcs[debug_level](debug_message.str().c_str());

        if (debug_level == CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ASSERTION) abort();
    }

    static void
    resetDebugFunctions()
    {
        for (auto &func : debug_funcs) {
            func = defaultPrint;
        }
    }

    static void
    setDebugFunction(const CompressionUtilsDebugLevel debug_level, DebugFunction function)
    {
        if (static_cast<int>(debug_level) > max_debug_level) return;
        debug_funcs[static_cast<int>(debug_level)] = function;
    }

    template <typename T>
    ZlibDebugStream & operator<<(const T &message) { debug_message << message; return *this; }

private:
    ostringstream debug_message;
    CompressionUtilsDebugLevel debug_level;

    static array<DebugFunction, max_debug_level + 1> debug_funcs;
};

array<DebugFunction, max_debug_level + 1> ZlibDebugStream::debug_funcs = {
    defaultPrint, // CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_TRACE
    defaultPrint, // CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_DEBUG
    defaultPrint, // CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_INFO
    defaultPrint, // CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_WARNING
    defaultPrint, // CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ERROR
    defaultPrint  // CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ASSERTION
};

#define zlibDbgError ZlibDebugStream(CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ERROR)
#define zlibDbgAssertion ZlibDebugStream(CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ASSERTION)

static const int default_num_window_bits = 15; // Default used by zlib.
static const int default_compression_level = Z_DEFAULT_COMPRESSION;
static const int default_compression_method = Z_DEFLATED;
static const int default_mem_level = 8; // Default recommended in zlib documentation.
static const int default_strategy = Z_DEFAULT_STRATEGY;

static const int zlib_ok_return_value = Z_OK;
static const int zlib_stream_done_return_value = Z_STREAM_END;
static const int zlib_bad_stream_state_error = Z_STREAM_ERROR;
static const int zlib_invalid_data_error = Z_DATA_ERROR;
static const int zlib_out_of_memory_error = Z_MEM_ERROR;
static const int zlib_version_mismatch_error = Z_VERSION_ERROR;
static const int zlib_buf_error = Z_BUF_ERROR;

static const int zlib_finish_flush = Z_FINISH;
static const int zlib_sync_flush = Z_SYNC_FLUSH;
static const int zlib_no_flush = Z_NO_FLUSH;

struct CompressionStream
{
    CompressionStream()
        :
    br_encoder_state(nullptr),
    br_decoder_state(nullptr)
    {
        bzero(&stream, sizeof(z_stream));
    }

    ~CompressionStream() { fini(); }

    tuple<basic_string<unsigned char>, bool>
    decompress(const unsigned char *data, uint32_t size)
    {
        if (state == TYPE::UNINITIALIZED && size > 0 && isBrotli(data, size)) return decompressBrotli(data, size);

        if (state == TYPE::DECOMPRESS_BROTLI) return decompressBrotli(data, size);

        initInflate();
        if (state != TYPE::DECOMPRESS) throw runtime_error("Could not start decompression");

        stream.avail_in = size;
        stream.next_in = data;

        vector<unsigned char> work_space;
        work_space.reserve(4096);
        basic_string<unsigned char> res;
        int retries = 0;

        while (stream.avail_in != 0) {
            stream.avail_out = work_space.capacity();
            stream.next_out = work_space.data();

            auto old_total_out = stream.total_out;

            auto inflate_res = inflate(&stream, zlib_no_flush);

            if (inflate_res != Z_OK && inflate_res != Z_STREAM_END) {
                fini();
                throw runtime_error("error in 'inflate': " + getZlibError(inflate_res));
            }

            if (stream.total_out != old_total_out) {
                res.append(work_space.data(), stream.total_out - old_total_out);
            } else {
                ++retries;
                if (retries > max_retries) {
                    fini();
                    throw runtime_error("No results from inflate more than three times");
                }
            }

            if (inflate_res == Z_STREAM_END) {
                fini();
                return make_tuple(res, true);
            }
        }

        return make_tuple(res, false);
    }

    basic_string<unsigned char>
    compress(CompressionType type, const unsigned char *data, uint32_t size, int is_last_chunk)
    {
        if (type == CompressionType::BROTLI) return compressBrotli(data, size, is_last_chunk);
        initDeflate(type);
        if (state != TYPE::COMPRESS) throw runtime_error("Could not start compression");

        stream.avail_in = size;
        stream.next_in = data;

        vector<unsigned char> work_space;
        work_space.reserve(deflateBound(&stream, stream.avail_in));
        basic_string<unsigned char> res;
        int retries = 0;

        while (stream.avail_in != 0 || is_last_chunk) {
            stream.avail_out = work_space.capacity();
            stream.next_out = work_space.data();

            auto old_total_out = stream.total_out;

            int deflate_res = deflate(&stream, is_last_chunk ? zlib_finish_flush : zlib_sync_flush);

            if (deflate_res != Z_OK && deflate_res != Z_STREAM_END) {
                fini();
                throw runtime_error("error in 'deflate': " + getZlibError(deflate_res));
            }
            if (stream.total_out != old_total_out) {
                res.append(work_space.data(), stream.total_out - old_total_out);
            } else {
                ++retries;
                if (retries > max_retries) {
                    fini();
                    throw runtime_error("No results from deflate more than three times");
                }
            }
            if (deflate_res == Z_STREAM_END) {
                fini();
                return res;
            }
        }

        return res;
    }

private:
    void
    initInflate()
    {
        if (state != TYPE::UNINITIALIZED) return;

        auto init_status = inflateInit2(&stream, default_num_window_bits + 32);
        if (init_status != zlib_ok_return_value) {
            throw runtime_error(
                "Failed to initialize decompression stream. Error: " + getZlibError(init_status)
            );
        }

        state = TYPE::DECOMPRESS;
    }

    void
    initDeflate(CompressionType type)
    {
        if (state != TYPE::UNINITIALIZED) return;

        int num_history_window_bits;
        switch (type) {
            case CompressionType::GZIP: {
                num_history_window_bits = default_num_window_bits + 16;
                break;
            }
            case CompressionType::ZLIB: {
                num_history_window_bits = default_num_window_bits;
                break;
            }
            case CompressionType::BROTLI: {
                zlibDbgAssertion << "Brotli compression should use compressBrotli()";
                return;
            }
            default: {
                zlibDbgAssertion
                    << "Invalid compression type value: "
                    << static_cast<int>(type);
                return;
            }
        }

        int init_status = deflateInit2(
            &stream,
            default_compression_level,
            default_compression_method,
            num_history_window_bits,
            default_mem_level,
            default_strategy
        );
        if (init_status != zlib_ok_return_value) {
            throw runtime_error(
                "Failed to initialize compression stream. Error: " + getZlibError(init_status)
            );
        }

        state = TYPE::COMPRESS;
    }

    basic_string<unsigned char>
    compressBrotli(const unsigned char *data, uint32_t size, int is_last_chunk)
    {
        if (state == TYPE::UNINITIALIZED) {
            br_encoder_state = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
            if (!br_encoder_state) throw runtime_error("Failed to create Brotli encoder state");

            BrotliEncoderSetParameter(br_encoder_state, BROTLI_PARAM_QUALITY, BROTLI_DEFAULT_QUALITY);
            BrotliEncoderSetParameter(br_encoder_state, BROTLI_PARAM_LGWIN, BROTLI_DEFAULT_WINDOW);
            state = TYPE::COMPRESS_BROTLI;
        } else if (state != TYPE::COMPRESS_BROTLI) {
            throw runtime_error("Compression stream in inconsistent state for Brotli compression");
        }

        basic_string<unsigned char> output;
        vector<uint8_t> buffer(16384);
        int retries = 0;
        const uint8_t* next_in = data;
        size_t available_in = size;

        while (available_in > 0 || is_last_chunk) {
            size_t available_out = buffer.size();
            uint8_t* next_out = buffer.data();


            BrotliEncoderOperation op = is_last_chunk ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS;
            auto brotli_success = BrotliEncoderCompressStream(
                br_encoder_state,
                op,
                &available_in,
                &next_in,
                &available_out,
                &next_out,
                nullptr
            );

            if (brotli_success == BROTLI_FALSE) {
                fini();
                throw runtime_error("Brotli compression error");
            }

            size_t bytes_written = buffer.size() - available_out;
            if (bytes_written > 0) {
                output.append(buffer.data(), bytes_written);
                retries = 0;
            } else {
                retries++;
                if (retries > max_retries) {
                    fini();
                    throw runtime_error("Brotli compression error: Exceeded retry limit.");
                }
            }

            if (BrotliEncoderIsFinished(br_encoder_state)) break;

            if (available_in == 0 && !is_last_chunk) break;
        }

        if (is_last_chunk) fini();

        return output;
    }

    tuple<basic_string<unsigned char>, bool>
    decompressBrotli(const unsigned char *data, uint32_t size)
    {
        if (state != TYPE::DECOMPRESS_BROTLI) {
            br_decoder_state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);

            if (!br_decoder_state) throw runtime_error("Failed to create Brotli decoder state");

            BrotliDecoderSetParameter(br_decoder_state, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1u);
            state = TYPE::DECOMPRESS_BROTLI;
        }

        basic_string<unsigned char> output;
        const uint8_t* next_in = data;
        size_t available_in = size;

        size_t buffer_size = max<size_t>(size * 4, default_brotli_buffer_size);
        vector<uint8_t> buffer(buffer_size);
        
        // Use a constant ratio for max buffer size relative to input size
        const size_t max_buffer_size = 256 * 1024 * 1024; // 256 MB max buffer size

        while (true) {
            size_t available_out = buffer.size();
            uint8_t* next_out = buffer.data();

            BrotliDecoderResult result = BrotliDecoderDecompressStream(
                br_decoder_state,
                &available_in,
                &next_in,
                &available_out,
                &next_out,
                nullptr
            );

            if (result == BROTLI_DECODER_RESULT_ERROR) {
                fini();
                auto error_msg = string(BrotliDecoderErrorString(BrotliDecoderGetErrorCode(br_decoder_state)));
                throw runtime_error("Brotli decompression error: " + error_msg);
            }

            // Handle any produced output
            size_t bytes_produced = buffer.size() - available_out;
            if (bytes_produced > 0) {
                output.append(buffer.data(), bytes_produced);
            }

            if (result == BROTLI_DECODER_RESULT_SUCCESS) {
                bool is_finished = BrotliDecoderIsFinished(br_decoder_state);
                if (is_finished) fini();
                return make_tuple(output, is_finished);
            }

            if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
                // Check if we've exceeded the maximum buffer size limit
                if (buffer.size() >= max_buffer_size) {
                    fini();
                    throw runtime_error("Brotli decompression buffer size limit exceeded - possibly corrupted data");
                }
                
                // Resize buffer to accommodate more output
                size_t new_size = min(buffer.size() * 2, max_buffer_size);
                buffer.resize(new_size);
                continue; // Continue with the same input, new buffer
            }

            // If we reach here, we need more input but have no more to provide
            if (available_in == 0) {
                // No more input data available, return what we have so far
                return make_tuple(output, false);
            }
        }

        return make_tuple(output, false);
    }

    bool
    isBrotli(const unsigned char *data, uint32_t size)
    {
        if (size < 4) return false;

        BrotliDecoderState* test_decoder = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        if (!test_decoder) return false;

        const uint8_t* next_in = data;
        size_t available_in = min<size_t>(size, brotli_decompression_probe_size);
        uint8_t output[brotli_decompression_probe_size];
        size_t available_out = sizeof(output);
        uint8_t* next_out = output;

        BrotliDecoderResult result = BrotliDecoderDecompressStream(
            test_decoder,
            &available_in,
            &next_in,
            &available_out,
            &next_out,
            nullptr
        );

        bool is_brotli = false;

        if (
            result != BROTLI_DECODER_RESULT_ERROR &&
            (
                available_out < sizeof(output) ||
                available_in < min<size_t>(size, brotli_decompression_probe_size)
            )
        ) {
            is_brotli = true;
        }

        BrotliDecoderDestroyInstance(test_decoder);
        if (is_brotli) {
            br_decoder_state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
            BrotliDecoderSetParameter(br_decoder_state, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1u);
            state = TYPE::DECOMPRESS_BROTLI;
            return true;
        }
        return false;
    }

    void
    fini()
    {
        int end_stream_res = zlib_ok_return_value;

        if (state == TYPE::DECOMPRESS) end_stream_res = inflateEnd(&stream);
        if (state == TYPE::COMPRESS) end_stream_res = deflateEnd(&stream);

        if (br_encoder_state) {
            BrotliEncoderDestroyInstance(br_encoder_state);
            br_encoder_state = nullptr;
        }

        if (br_decoder_state) {
            BrotliDecoderDestroyInstance(br_decoder_state);
            br_decoder_state = nullptr;
        }

        if (end_stream_res != zlib_ok_return_value && end_stream_res != Z_DATA_ERROR) {
            zlibDbgError << "Failed to clean state: " << getZlibError(end_stream_res);
        }

        state = TYPE::UNINITIALIZED;
    }

    string
    getZlibError(int zlibErrorCode)
    {
        switch (zlibErrorCode) {
            case zlib_buf_error:
                return "No progress was possible (possibly no more input data or not enough output buffer space)";
            case zlib_bad_stream_state_error:
                return "Inconsistent compression stream state";
            case zlib_invalid_data_error:
                return "Invalid or corrupted stream data";
            case zlib_out_of_memory_error:
                return "Out of memory";
            case zlib_version_mismatch_error:
                return "zlib version mismatch";
            default:
                return "zlib error occurred. Error code: " + to_string(zlibErrorCode);
        }
    }

    z_stream stream;
        enum class TYPE {
        UNINITIALIZED,
        COMPRESS,
        DECOMPRESS,
        COMPRESS_BROTLI,
        DECOMPRESS_BROTLI
    } state = TYPE::UNINITIALIZED;

    BrotliEncoderState* br_encoder_state = nullptr;
    BrotliDecoderState* br_decoder_state = nullptr;
};

void
resetCompressionDebugFunctionsToStandardError()
{
    ZlibDebugStream::resetDebugFunctions();
}

void
setCompressionDebugFunction(const CompressionUtilsDebugLevel debug_level, void (*debug_function)(const char *))
{
    ZlibDebugStream::setDebugFunction(debug_level, debug_function);
}

CompressionStream *
initCompressionStream()
{
    return new CompressionStream();
}

void
finiCompressionStream(CompressionStream *compression_stream)
{
    delete compression_stream;
}

static unsigned char *
duplicateMemory(const basic_string<unsigned char> &str)
{
    auto res = static_cast<unsigned char *>(malloc(str.size()));

    if (res == nullptr) throw bad_alloc();

    memcpy(res, str.data(), str.size());

    return res;
}

CompressionResult
compressData(
    CompressionStream *compression_stream,
    const CompressionType compression_type,
    const uint32_t data_size,
    const unsigned char *uncompressed_data,
    const int is_last_chunk
)
{
    CompressionResult result;

    try {
        if (compression_stream == nullptr) throw invalid_argument("Compression stream is NULL");
        if (uncompressed_data == nullptr) throw invalid_argument("Data pointer is NULL");

        auto compress = compression_stream->compress(compression_type, uncompressed_data, data_size, is_last_chunk);
        result.output = duplicateMemory(compress);
        result.num_output_bytes = compress.size();
        result.ok = 1;
    } catch (const exception &e) {
        zlibDbgError << "Compression failed " << e.what();

        result.ok = 0;
    }

    return result;
}

DecompressionResult
decompressData(
    CompressionStream *compression_stream,
    const uint32_t compressed_data_size,
    const unsigned char *compressed_data
)
{
    DecompressionResult result;

    try {
        if (compression_stream == nullptr) throw invalid_argument("Compression stream is NULL");
        if (compressed_data == nullptr) throw invalid_argument("Data pointer is NULL");
        if (compressed_data_size == 0) throw invalid_argument("Data size is 0");

        auto decompress = compression_stream->decompress(compressed_data, compressed_data_size);
        result.output = duplicateMemory(get<0>(decompress));
        result.num_output_bytes = get<0>(decompress).size();
        result.is_last_chunk = get<1>(decompress);
        result.ok = 1;
    } catch (const exception &e) {
        zlibDbgError << "Decompression failed " << e.what();

        result.ok = 0;
    }

    return result;
}
