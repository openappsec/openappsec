#include <fstream>

#include "cptest.h"
#include "compression_utils.h"
#include "buffer.h"

using namespace std;
using namespace testing;

using ErrorHook = function<void(const char *)>;

USE_DEBUG_FLAG(D_COMPRESSION);

class CompressionUtilsTest : public Test
{
public:
    CompressionUtilsTest()
    {
        Debug::setUnitTestFlag(D_COMPRESSION, Debug::DebugLevel::ERROR);
        Debug::setNewDefaultStdout(&capture_debug);

        setCompressionDebugFunction(
            CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ERROR,
            [](const char *debug_message) { dbgError(D_COMPRESSION) << debug_message; }
        );
        setCompressionDebugFunction(
            CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ASSERTION,
            [](const char *assert_message) { dbgAssert(false) << assert_message; }
        );
    }

    ~CompressionUtilsTest()
    {
        resetOutputStream();
    }

    void
    resetOutputStream()
    {
        capture_debug.str("");
        Debug::setNewDefaultStdout(&cout);
        resetCompressionDebugFunctionsToStandardError();
    }

    string
    readTestFileContents(const string &file_name)
    {
        string file_path = cptestFnameInExeDir(test_files_dir_name + "/" + file_name);
        ifstream test_string_file(file_path);
        stringstream string_stream;
        string_stream << test_string_file.rdbuf();

        return string_stream.str();
    }

    Maybe<string>
    compressString(
        const CompressionType compression_type,
        const string &uncompressed_string,
        const bool last_chunk = true,
        CompressionStream *compression_stream = nullptr
    )
    {
        auto disposable_compression_stream = initCompressionStream();

        CompressionStream *compression_stream_to_use =
            compression_stream == nullptr ?
                disposable_compression_stream :
                compression_stream;

        unsigned char *input_data = reinterpret_cast<unsigned char *>(const_cast<char *>(uncompressed_string.c_str()));
        CompressionResult compress_data_result = compressData(
            compression_stream_to_use,
            compression_type,
            uncompressed_string.size(),
            input_data,
            last_chunk ? 1 : 0
        );
        finiCompressionStream(disposable_compression_stream);

        if (compress_data_result.ok == 0) return genError("compressString failed");

        auto compressed_string = string(
            reinterpret_cast<char *>(compress_data_result.output),
            compress_data_result.num_output_bytes
        );
        free(compress_data_result.output);

        return compressed_string;
    }

    Maybe<string>
    chunkedCompressString(const CompressionType compression_type, const string &uncompressed_string)
    {
        vector<string> input_string_chunks = splitIntoChunks(
            uncompressed_string,
            uncompressed_string.size() / chunk_size + 1
        );
        stringstream compressed_data_ss;
        auto compression_stream = initCompressionStream();
        for (uint32_t curr_chunk_index = 0; curr_chunk_index < input_string_chunks.size() - 1; curr_chunk_index++) {
            Maybe<string> compress_string_result = compressString(
                compression_type,
                input_string_chunks[curr_chunk_index],
                false,
                compression_stream
            );
            if (!compress_string_result.ok()) {
                finiCompressionStream(compression_stream);
                return genError("chunkedCompressString failed: " + compress_string_result.getErr());
            }

            compressed_data_ss << compress_string_result.unpack();
        }

        Maybe<string> compress_string_result = compressString(
            compression_type,
            input_string_chunks[input_string_chunks.size() - 1],
            true,
            compression_stream
        );
        finiCompressionStream(compression_stream);

        if (!compress_string_result.ok()) {
            return genError("chunkedCompressString failed: " + compress_string_result.getErr());
        }

        compressed_data_ss << compress_string_result.unpack();
        return compressed_data_ss.str();
    }

    Maybe<string>
    decompressString(
        const string &compressed_string,
        int *is_last_chunk = nullptr,
        CompressionStream *compression_stream = nullptr
    )
    {
        auto disposable_compression_stream = initCompressionStream();
        CompressionStream *compression_stream_to_use =
            compression_stream == nullptr ?
                disposable_compression_stream :
                compression_stream;

        unsigned char *compressed_data = reinterpret_cast<unsigned char *>(
            const_cast<char *>(
                compressed_string.c_str()
            )
        );

        int disposable_is_last_chunk_indicator = 0;
        int *is_last_chunk_indicator_to_use =
            is_last_chunk == nullptr ?
                &disposable_is_last_chunk_indicator :
                is_last_chunk;

        DecompressionResult decompress_data_result = decompressData(
            compression_stream_to_use,
            compressed_string.size(),
            compressed_data
        );
        *is_last_chunk_indicator_to_use = decompress_data_result.is_last_chunk;
        finiCompressionStream(disposable_compression_stream);
        if (decompress_data_result.ok == 0) return genError("decompressString failed");

        auto decompressed_string = string(
            reinterpret_cast<char *>(decompress_data_result.output),
            decompress_data_result.num_output_bytes
        );
        free(decompress_data_result.output);

        return decompressed_string;
    }

    Maybe<string>
    chunkedDecompressString(const string &compressed_string)
    {
        auto compression_stream = initCompressionStream();
        int is_last_chunk = 0;
        stringstream decompressed_data_ss;

        vector<string> input_string_chunks = splitIntoChunks(
            compressed_string,
            compressed_string.size() / chunk_size + 1
        );

        for (uint32_t curr_chunk_index = 0; curr_chunk_index < input_string_chunks.size(); curr_chunk_index++) {
            Maybe<string> decompress_string_result = decompressString(
                input_string_chunks[curr_chunk_index],
                &is_last_chunk,
                compression_stream
            );
            if (!decompress_string_result.ok()) {
                finiCompressionStream(compression_stream);
                return genError("chunkedDecompress failed: " + decompress_string_result.getErr());
            }

            decompressed_data_ss << decompress_string_result.unpack();
        }

        finiCompressionStream(compression_stream);
        return decompressed_data_ss.str();
    }

    bool
    performCompressionNullPointerTest()
    {
        static const vector<int> possible_last_chunk_values = { 0, 1 };
        string compress_test_string = readTestFileContents(chunk_sized_string_file_name);
        string decompress_test_string = readTestFileContents(chunk_sized_gzip_file_name);

        for (CompressionType single_compression_type : compression_types) {
            for (int single_possible_last_chunk_value : possible_last_chunk_values) {
                CompressionResult result = compressData(
                    nullptr,
                    single_compression_type,
                    compress_test_string.size(),
                    reinterpret_cast<unsigned char *>(const_cast<char *>(compress_test_string.c_str())),
                    single_possible_last_chunk_value
                );

                if (result.ok) return false;
            }
        }

        DecompressionResult result = decompressData(
            nullptr,
            decompress_test_string.size(),
            reinterpret_cast<unsigned char *>(const_cast<char *>(decompress_test_string.c_str()))
        );

        if (result.ok) return false;

        return true;
    }

    vector<string>
    splitIntoChunks(const string &data, const uint32_t num_data_chunks)
    {
        vector<string> data_chunks;

        uint32_t num_data_chunks_to_use = min(static_cast<uint32_t>(data.size()), num_data_chunks);
        if (num_data_chunks_to_use == 1) return { data };

        uint32_t chunk_size =  data.size() / num_data_chunks;
        for (uint32_t curr_chunk_index = 0; curr_chunk_index < num_data_chunks_to_use - 1; curr_chunk_index++) {
            data_chunks.push_back(string(data.c_str() + curr_chunk_index * chunk_size, chunk_size));
        }

        uint32_t accumulated_chunks_size = (num_data_chunks_to_use - 1) * chunk_size;
        data_chunks.push_back(string(data.c_str() + accumulated_chunks_size, data.size() - accumulated_chunks_size));

        return data_chunks;
    }

    uint32_t
    calcCompressedDataSizeBound(const uint32_t compressed_data_size)
    {
        return 2 * compressed_data_size;
    }

    ostringstream capture_debug;

    const string simple_test_string = "Test data for compression utilities library";
    const string chunk_sized_string_file_name = "chunk_sized_string";
    const string chunk_sized_gzip_file_name = "chunk_sized_compressed_file.gz";
    const string chunk_sized_zlib_file_name = "chunk_sized_compressed_file.zz";
    const string multi_chunk_sized_string_file_name = "multiple_chunk_sized_string";
    const string multi_chunk_sized_gzip_file_name = "multiple_chunk_sized_compressed_file.gz";
    const string multi_chunk_sized_zlib_file_name = "multiple_chunk_sized_compressed_file.zz";
    const vector<string> chunk_sized_compressed_files = { chunk_sized_gzip_file_name, chunk_sized_zlib_file_name };
    const vector<string> multi_chunk_sized_compressed_files = {
        multi_chunk_sized_gzip_file_name,
        multi_chunk_sized_zlib_file_name
    };

    const vector<CompressionType> compression_types = { CompressionType::GZIP, CompressionType::ZLIB };
    const uint32_t chunk_size = 32768;

private:
    const string test_files_dir_name = "test_files";
};

TEST_F(CompressionUtilsTest, CompressAndDecompressSimpleString)
{
    for (auto single_compression_type : compression_types) {
        Maybe<string> compressed_string_maybe = compressString(
            single_compression_type,
            simple_test_string
        );
        EXPECT_TRUE(compressed_string_maybe.ok());

        Maybe<string> decompressed_string_maybe = decompressString(compressed_string_maybe.unpack());
        EXPECT_TRUE(decompressed_string_maybe.ok());

        EXPECT_EQ(simple_test_string, decompressed_string_maybe.unpack());
    }
}

TEST_F(CompressionUtilsTest, CompressAndDecompressChunkSizedString)
{
    string test_string = readTestFileContents(chunk_sized_string_file_name);

    for (auto single_compression_type : compression_types) {
        Maybe<string> compressed_string_maybe = compressString(
            single_compression_type,
            test_string
        );
        EXPECT_TRUE(compressed_string_maybe.ok());

        Maybe<string> decompressed_string_maybe = decompressString(compressed_string_maybe.unpack());
        EXPECT_TRUE(decompressed_string_maybe.ok());

        EXPECT_EQ(test_string, decompressed_string_maybe.unpack());
    }
}

TEST_F(CompressionUtilsTest, CompressMultipleChunkSizedStringAndDecompress)
{
    string test_string = readTestFileContents(multi_chunk_sized_string_file_name);
    for (auto single_compression_type : compression_types) {
        Maybe<string> chunked_compress_result = chunkedCompressString(single_compression_type, test_string);
        EXPECT_TRUE(chunked_compress_result.ok());

        Maybe<string> chunked_decompress_result = chunkedDecompressString(chunked_compress_result.unpack());
        EXPECT_TRUE(chunked_decompress_result.ok());

        EXPECT_EQ(chunked_decompress_result.unpack(), test_string);
    }
}

TEST_F(CompressionUtilsTest, DecompressChunkSizedCompressedFile)
{
    for (const auto &single_compressed_file_name : chunk_sized_compressed_files) {
        string test_string = readTestFileContents(single_compressed_file_name);

        string expected_decompressed_string = readTestFileContents(chunk_sized_string_file_name);
        Maybe<string> decompressed_string_result = decompressString(test_string);
        EXPECT_TRUE(decompressed_string_result.ok());
        EXPECT_EQ(decompressed_string_result.unpack(), expected_decompressed_string);
    }
}

TEST_F(CompressionUtilsTest, DecompressMultipleChunkSizedCompressedFile)
{
    for (const auto &single_compressed_file_name : multi_chunk_sized_compressed_files) {
        string test_string = readTestFileContents(single_compressed_file_name);

        Maybe<string> chunked_decompress_result = chunkedDecompressString(test_string);
        EXPECT_TRUE(chunked_decompress_result.ok());

        string expected_decompressed_string = readTestFileContents(multi_chunk_sized_string_file_name);
        EXPECT_EQ(chunked_decompress_result.unpack(), expected_decompressed_string);
    }
}

TEST_F(CompressionUtilsTest, TestEmptyBuffer)
{
    for (CompressionType compression_type : compression_types) {
        auto compression_stream = initCompressionStream();
        stringstream compressed_stream;

        Maybe<string> compressed_string = compressString(
            compression_type,
            simple_test_string,
            false,
            compression_stream
        );
        EXPECT_TRUE(compressed_string.ok());
        compressed_stream << compressed_string.unpack();

        compressed_string = compressString(
            compression_type,
            "",
            true,
            compression_stream
        );
        finiCompressionStream(compression_stream);
        EXPECT_TRUE(compressed_string.ok());
        compressed_stream << compressed_string.unpack();

        Buffer compressed_buffer(compressed_stream.str());

        int is_last_chunk;
        auto decompression_stream = initCompressionStream();

        Maybe<string> decompressed_string = decompressString(
            compressed_stream.str(),
            &is_last_chunk,
            decompression_stream
        );

        EXPECT_TRUE(decompressed_string.ok());
        EXPECT_EQ(decompressed_string.unpack(), simple_test_string);
        finiCompressionStream(decompression_stream);
    }
}

TEST_F(CompressionUtilsTest, CompressionStreamNullPointer)
{
    EXPECT_TRUE(performCompressionNullPointerTest());
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Compression failed Compression stream is NULL")
    );

    resetOutputStream();
    EXPECT_TRUE(performCompressionNullPointerTest());
    EXPECT_EQ(capture_debug.str(), string());
}

TEST_F(CompressionUtilsTest, InputDataBufferNullPointer)
{
    static const vector<int> possible_last_chunk_values = { 0, 1 };
    string compress_test_string = readTestFileContents(chunk_sized_string_file_name);
    auto compression_stream = initCompressionStream();

    for (CompressionType single_compression_type : compression_types) {
        for (int single_possible_last_chunk_value : possible_last_chunk_values) {
            CompressionResult result = compressData(
                compression_stream,
                single_compression_type,
                compress_test_string.size(),
                nullptr,
                single_possible_last_chunk_value
            );

            EXPECT_EQ(result.ok, 0);
        }
    }

    string decompress_test_string = readTestFileContents(chunk_sized_gzip_file_name);
    finiCompressionStream(compression_stream);
    compression_stream = initCompressionStream();

    DecompressionResult result = decompressData(
        compression_stream,
        decompress_test_string.size(),
        nullptr
    );

    EXPECT_EQ(result.ok, 0);
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Compression failed Data pointer is NULL")
    );
    finiCompressionStream(compression_stream);
}

TEST_F(CompressionUtilsTest, DecompressPlainText)
{
    Maybe<string> decompress_string_result = decompressString(simple_test_string);

    EXPECT_FALSE(decompress_string_result.ok());
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("error in 'inflate': Invalid or corrupted stream data")
    );
}
