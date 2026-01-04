// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <iostream>
#include <streambuf>
#include <vector>
#include <memory>
#include "compression_utils.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_SERIALIZE);

// Forward declarations
class WaapComponent;

void yieldIfPossible(const std::string &func, int line);

#define YIELD_IF_POSSIBLE() yieldIfPossible(__FUNCTION__, __LINE__)

//
// Buffered output stream that compresses and encrypts data when flushing
//
// Usage example:
//   std::stringstream ss;
//   BufferedCompressedOutputStream compressed_stream(ss);
//   compressed_stream << "Hello, World!";
//   compressed_stream.flush(); // Data is compressed, encrypted, and written to ss
class BufferedCompressedOutputStream : public std::ostream
{
public:
    explicit BufferedCompressedOutputStream(std::ostream &underlying_stream);
    ~BufferedCompressedOutputStream();

    // Manual flush to compress, encrypt and write data
    void flush();
    void close();

private:
    class CompressedBuffer : public std::streambuf, Singleton::Consume<I_Encryptor>
    {
    public:
        explicit CompressedBuffer(std::ostream &underlying_stream);
        ~CompressedBuffer();

        // Public method to flush the buffer
        void flushAndClose();
        void flushBuffer();

    protected:
        virtual int overflow(int c) override;
        virtual std::streamsize xsputn(const char* s, std::streamsize n) override;
        virtual int sync() override;

    private:
        // Compress and encrypt buffer; is_last indicates final chunk
        bool compressAndEncryptBuffer(bool is_last);
        std::ostream &m_underlying_stream;
        std::vector<char> m_buffer;
        static const size_t BUFFER_SIZE = 16 * 1024; // 16KiB
        CompressionStream* m_compression_stream;
        bool m_closed;
    };

    std::unique_ptr<CompressedBuffer> m_buffer;
};


// Buffered input stream that decrypts and decompresses data when reading
//
// Usage example:
//   std::stringstream ss("encrypted compressed data");
//   BufferedCompressedInputStream decompressed_stream(ss);
//   std::string line;
//   std::getline(decompressed_stream, line); // Data is decrypted and decompressed

class BufferedCompressedInputStream : public std::istream
{
public:
    explicit BufferedCompressedInputStream(std::istream &underlying_stream);
    ~BufferedCompressedInputStream();

private:
    class DecompressedBuffer : public std::streambuf
    {
    public:
        explicit DecompressedBuffer(std::istream &underlying_stream);
        ~DecompressedBuffer();

    protected:
        virtual int underflow() override;
        virtual std::streamsize xsgetn(char* s, std::streamsize n) override;

    private:
        bool fillBuffer();
        bool processNextChunk();
        bool decryptChunk(const std::vector<char> &encrypted_chunk, std::vector<char> &decrypted_chunk);
        bool decompressChunk(const std::vector<char> &compressed_chunk, std::vector<char> &decompressed_chunk);
        
        std::istream &m_underlying_stream;
        std::vector<char> m_buffer; // Output buffer for decompressed data
        std::vector<char> m_encrypted_buffer; // Buffer for encrypted data from stream
        std::vector<char> m_compressed_buffer; // Buffer for decrypted but still compressed data
        std::vector<char> m_decompressed_buffer; // Buffer for decompressed data chunks
        size_t m_decompressed_pos; // Current position in decompressed buffer
        
        static const size_t OUTPUT_BUFFER_SIZE = 64 * 1024; // 64KiB output buffer
        static const size_t CHUNK_SIZE = 16 * 1024; // 16KiB chunks for processing
        
        CompressionStream* m_compression_stream;
        bool m_eof_reached;
        bool m_stream_finished; // Whether we've finished processing the entire stream
    };

    std::unique_ptr<DecompressedBuffer> m_buffer;
};
