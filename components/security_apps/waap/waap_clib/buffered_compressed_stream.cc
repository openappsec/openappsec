// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

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

#include "buffered_compressed_stream.h"
#include "waap.h"
#include "compression_utils.h"
#include <sstream>

USE_DEBUG_FLAG(D_WAAP_SERIALIZE);

using namespace std;

void yieldIfPossible(const string &func, int line)
{
    // check mainloop exists and current routine is not the main routine
    if (Singleton::exists<I_MainLoop>() &&
        Singleton::Consume<I_MainLoop>::by<WaapComponent>()->getCurrentRoutineId().ok())
    {
        dbgDebug(D_WAAP_SERIALIZE) << "Yielding to main loop from: " << func << ":" << line;
        Singleton::Consume<I_MainLoop>::by<WaapComponent>()->yield(false);
    }
}

// Static member definitions
const size_t BufferedCompressedOutputStream::CompressedBuffer::BUFFER_SIZE;
const size_t BufferedCompressedInputStream::DecompressedBuffer::OUTPUT_BUFFER_SIZE;
const size_t BufferedCompressedInputStream::DecompressedBuffer::CHUNK_SIZE;

BufferedCompressedOutputStream::BufferedCompressedOutputStream(ostream &underlying_stream)
    :
        ostream(nullptr),
        m_buffer(make_unique<CompressedBuffer>(underlying_stream))
{
    rdbuf(m_buffer.get());
}

BufferedCompressedOutputStream::~BufferedCompressedOutputStream()
{
    try {
        close();
    } catch (exception &e) {
        // Destructor should not throw
        dbgWarning(D_WAAP_SERIALIZE) << "Exception in BufferedCompressedOutputStream destructor: " << e.what();
    }
}

void BufferedCompressedOutputStream::flush()
{
    if (m_buffer) {
        dbgTrace(D_WAAP_SERIALIZE) << "Flushing internal buffer...";
        m_buffer->flushBuffer(); // This will compress and encrypt the current buffer with is_last=false
                                // and flush the underlying stream.
    }
    // Do NOT call ostream::flush() here, as it would call sync() on our m_buffer,
    // which calls compressAndEncryptBuffer(true) and finalizes the GZIP stream prematurely.
    // The m_underlying_stream within m_buffer is flushed by compressAndEncryptBuffer itself.
}

void BufferedCompressedOutputStream::close()
{
    if (m_buffer) {
        dbgTrace(D_WAAP_SERIALIZE) << "Closing stream and flushing buffer...";
        m_buffer->flushAndClose();
    }
}

BufferedCompressedOutputStream::CompressedBuffer::CompressedBuffer(ostream &underlying_stream)
    :
    m_underlying_stream(underlying_stream),
    m_buffer(),
    m_compression_stream(nullptr),
    m_closed(false)
{
    m_buffer.reserve(BUFFER_SIZE);
    m_compression_stream = initCompressionStream();

}

BufferedCompressedOutputStream::CompressedBuffer::~CompressedBuffer()
{
    try {
        if (!m_closed) {
            sync();
        }
        if (m_compression_stream) {
            finiCompressionStream(m_compression_stream);
            m_compression_stream = nullptr;
        }
    } catch (exception &e) {
        // Destructor should not throw
        dbgWarning(D_WAAP_SERIALIZE) << "Exception in CompressedBuffer destructor: " << e.what();
    }
}

void BufferedCompressedOutputStream::CompressedBuffer::flushAndClose()
{
    sync();
}

int BufferedCompressedOutputStream::CompressedBuffer::overflow(int c)
{
    if (m_closed) {
        dbgTrace(D_WAAP_SERIALIZE) << "Stream is closed, returning EOF";
        return traits_type::eof();
    }

    if (c != traits_type::eof()) {
        m_buffer.push_back(static_cast<char>(c));
        dbgTrace(D_WAAP_SERIALIZE) << "Added char, buffer size now: " << m_buffer.size();
    }

    if (m_buffer.size() >= BUFFER_SIZE) {
        dbgTrace(D_WAAP_SERIALIZE) << "Buffer full, flushing...";
        compressAndEncryptBuffer(false);
    }

    return c;
}

streamsize BufferedCompressedOutputStream::CompressedBuffer::xsputn(const char* s, streamsize n)
{
    if (m_closed) {
        dbgDebug(D_WAAP_SERIALIZE) << "Stream is closed, returning 0";
        return 0;
    }

    dbgTrace(D_WAAP_SERIALIZE) << "Writing " << n << " bytes";
    streamsize written = 0;
    while (written < n) {
        size_t space_available = BUFFER_SIZE - m_buffer.size();
        size_t to_write = min(static_cast<size_t>(n - written), space_available);

        m_buffer.insert(m_buffer.end(), s + written, s + written + to_write);
        written += to_write;

        dbgTrace(D_WAAP_SERIALIZE) << "Wrote " << to_write << " bytes, total written: " << written
                                << ", buffer size: " << m_buffer.size();

        if (m_buffer.size() >= BUFFER_SIZE) {
            dbgTrace(D_WAAP_SERIALIZE) << "Buffer full, flushing...";
            compressAndEncryptBuffer(false);
        }
    }

    dbgTrace(D_WAAP_SERIALIZE) << "Completed, total written: " << written;
    return written;
}

int BufferedCompressedOutputStream::CompressedBuffer::sync()
{
    dbgTrace(D_WAAP_SERIALIZE) << "Called, closed=" << m_closed << ", buffer size=" << m_buffer.size();
    if (!m_closed) {
        bool success = compressAndEncryptBuffer(true); // Attempt final compression/encryption
        // Mark as closed REGARDLESS of the success of the attempt to ensure finalization logic
        // for this context isn't re-attempted if this call failed.
        m_closed = true;
        if (!success) {
            dbgWarning(D_WAAP_SERIALIZE) << "Final compression/encryption failed";
            return -1;
        }
        dbgTrace(D_WAAP_SERIALIZE) << "Stream closed successfully";
    } else {
        dbgDebug(D_WAAP_SERIALIZE) << "Stream already closed, skipping";
    }
    return 0;
}

void BufferedCompressedOutputStream::CompressedBuffer::flushBuffer()
{
    if (m_buffer.empty() || m_closed) {
        return;
    }

    dbgTrace(D_WAAP_SERIALIZE) << "Flushing buffer with " << m_buffer.size() << " bytes";
    compressAndEncryptBuffer(false);
}

bool BufferedCompressedOutputStream::CompressedBuffer::compressAndEncryptBuffer(bool is_last)
{
    // If the stream is already marked as closed at this buffer's level,
    // it means sync() has run, and everything, including encryption, has been finalized.
    if (m_closed) {
        dbgTrace(D_WAAP_SERIALIZE) << "Stream is already closed, skipping.";
        return true;
    }

    // Skip if there's nothing to compress and this is not the final flush
    if (m_buffer.empty() && !is_last) {
        dbgTrace(D_WAAP_SERIALIZE) << "Buffer empty and not last call, skipping.";
        return true;
    }

    dbgTrace(D_WAAP_SERIALIZE) << "Compressing and encrypting " << m_buffer.size() << " bytes, is_last: " << is_last;

    // Compress the buffer
    CompressionResult result = compressData(
        m_compression_stream,
        CompressionType::GZIP,
        static_cast<uint32_t>(m_buffer.size()),
        reinterpret_cast<const unsigned char*>(m_buffer.data()),
        is_last ? 1 : 0
    );

    if (!result.ok) {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to compress data";
        return false;
    }

    string compressed_data;
    if (result.output && result.num_output_bytes > 0) {
        compressed_data = string(reinterpret_cast<const char*>(result.output), result.num_output_bytes);
        free(result.output);
    }

    dbgDebug(D_WAAP_SERIALIZE) << "Compression complete: " << m_buffer.size()
                            << " bytes -> " << compressed_data.size() << " bytes";

    // Yield after compression to allow other routines to run
    YIELD_IF_POSSIBLE();

    string final_data = compressed_data;

    // Write to underlying stream only if we have data to write
    if (!final_data.empty()) {
        m_underlying_stream.write(final_data.c_str(), final_data.size());
        m_underlying_stream.flush();
    }

    m_buffer.clear();

    // Yield after writing chunk to allow other routines to run
    YIELD_IF_POSSIBLE();

    return true;
}

BufferedCompressedInputStream::BufferedCompressedInputStream(istream &underlying_stream)
    :
    istream(nullptr),
    m_buffer(make_unique<DecompressedBuffer>(underlying_stream))
{
    rdbuf(m_buffer.get());
}

BufferedCompressedInputStream::~BufferedCompressedInputStream()
{
    // DecompressedBuffer destructor will handle cleanup
}

BufferedCompressedInputStream::DecompressedBuffer::DecompressedBuffer(istream &underlying_stream)
    :
m_underlying_stream(underlying_stream),
    m_buffer(),
    m_encrypted_buffer(),
    m_compressed_buffer(),
    m_decompressed_buffer(),
    m_decompressed_pos(0),
    m_compression_stream(nullptr),
    m_eof_reached(false),
    m_stream_finished(false)
{
    m_buffer.resize(OUTPUT_BUFFER_SIZE);
    m_encrypted_buffer.reserve(CHUNK_SIZE);
    m_compressed_buffer.reserve(CHUNK_SIZE);
    m_decompressed_buffer.reserve(OUTPUT_BUFFER_SIZE);
    m_compression_stream = initCompressionStream();


    // Set buffer pointers to indicate empty buffer
    setg(m_buffer.data(), m_buffer.data(), m_buffer.data());
}

BufferedCompressedInputStream::DecompressedBuffer::~DecompressedBuffer()
{
    try {
        if (m_compression_stream) {
            finiCompressionStream(m_compression_stream);
            m_compression_stream = nullptr;
        }
    } catch (exception &e) {
        // Destructor should not throw
        dbgWarning(D_WAAP_SERIALIZE) << "Exception in DecompressedBuffer destructor: " << e.what();
    }
}

int BufferedCompressedInputStream::DecompressedBuffer::underflow()
{
    if (gptr() < egptr()) {
        return traits_type::to_int_type(*gptr());
    }

    if (m_eof_reached) {
        return traits_type::eof();
    }

    if (!fillBuffer()) {
        m_eof_reached = true;
        return traits_type::eof();
    }

    return traits_type::to_int_type(*gptr());
}

streamsize BufferedCompressedInputStream::DecompressedBuffer::xsgetn(char* s, streamsize n)
{
    streamsize total_read = 0;

    while (total_read < n) {
        if (gptr() >= egptr()) {
            if (!fillBuffer()) {
                m_eof_reached = true;
                break;
            }
        }

        streamsize available = egptr() - gptr();
        streamsize to_copy = min(n - total_read, available);

        memcpy(s + total_read, gptr(), to_copy);
        gbump(static_cast<int>(to_copy));
        total_read += to_copy;
    }

    return total_read;
}

bool BufferedCompressedInputStream::DecompressedBuffer::fillBuffer()
{
    if (m_eof_reached) {
        return false;
    }

    // If we have remaining data in the decompressed buffer, use it first
    if (m_decompressed_pos < m_decompressed_buffer.size()) {
        size_t remaining = m_decompressed_buffer.size() - m_decompressed_pos;
        size_t to_copy = min(remaining, OUTPUT_BUFFER_SIZE);

        memcpy(m_buffer.data(), m_decompressed_buffer.data() + m_decompressed_pos, to_copy);
        m_decompressed_pos += to_copy;

        // Set up the buffer pointers for streambuf:
        // eback() = m_buffer.data() (start of buffer)
        // gptr()  = m_buffer.data() (current position)
        // egptr() = m_buffer.data() + to_copy (end of valid data)
        setg(m_buffer.data(), m_buffer.data(), m_buffer.data() + to_copy);

        dbgTrace(D_WAAP_SERIALIZE) << "Serving " << to_copy << " bytes from existing decompressed buffer";

        // Yield after serving data from buffer to allow other routines to run
        YIELD_IF_POSSIBLE();
        return true;
    }

    // Need to process the next chunk
    if (!processNextChunk()) {
        m_eof_reached = true;
        return false;
    }

    // Now try again with the new data
    return fillBuffer();
}

bool BufferedCompressedInputStream::DecompressedBuffer::processNextChunk()
{
    while (true) {
        if (m_stream_finished) {
            return false;
        }

        // Read a chunk of encrypted data from the underlying stream
        if (m_encrypted_buffer.size() < CHUNK_SIZE) {
            m_encrypted_buffer.resize(CHUNK_SIZE);
        }
        m_underlying_stream.read(m_encrypted_buffer.data(), CHUNK_SIZE);
        streamsize bytes_read = m_underlying_stream.gcount();

        if (bytes_read <= 0) {
            m_stream_finished = true;

            // End of stream - no more data to process
            dbgTrace(D_WAAP_SERIALIZE) << "Reached end of input stream";
            return false;
        }

        m_encrypted_buffer.resize(bytes_read);

        dbgTrace(D_WAAP_SERIALIZE) << "Read " << bytes_read << " encrypted bytes from stream";

        // Decrypt the chunk
        std::vector<char> decrypted_chunk;
        if (!decryptChunk(m_encrypted_buffer, decrypted_chunk)) {
            dbgWarning(D_WAAP_SERIALIZE) << "Failed to decrypt chunk";
            break;
        }

        // Decompress the chunk
        std::vector<char> decompressed_chunk;
        if (!decompressChunk(decrypted_chunk, decompressed_chunk)) {
            dbgWarning(D_WAAP_SERIALIZE) << "Failed to decompress chunk";
            break;
        }

        if (decompressed_chunk.empty()) {
            dbgTrace(D_WAAP_SERIALIZE) << "Decompressed chunk is empty, skipping";
            continue; // Nothing to add to the buffer
        }
        // Replace the decompressed buffer with new data using swap to avoid unnecessary allocations
        m_decompressed_buffer.swap(decompressed_chunk);
        m_decompressed_pos = 0;

        dbgTrace(D_WAAP_SERIALIZE) << "Processed chunk: " << bytes_read
                                << " encrypted -> " << decrypted_chunk.size()
                                << " compressed -> " << m_decompressed_buffer.size() << " decompressed";

        // Yield after processing chunk to allow other routines to run
        YIELD_IF_POSSIBLE();
        return true;
    }
    return false;
}

bool BufferedCompressedInputStream::DecompressedBuffer::decryptChunk(
    const std::vector<char> &encrypted_chunk,
    std::vector<char> &decrypted_chunk)
{

    // No encryption - just copy the data
    decrypted_chunk = encrypted_chunk;
    return true;
}

bool BufferedCompressedInputStream::DecompressedBuffer::decompressChunk(
    const std::vector<char> &compressed_chunk,
    std::vector<char> &decompressed_chunk)
{
    if (compressed_chunk.empty()) {
        return true; // Nothing to decompress
    }

    // Use the streaming decompression
    DecompressionResult result = decompressData(
        m_compression_stream,
        compressed_chunk.size(),
        reinterpret_cast<const unsigned char*>(compressed_chunk.data())
    );

    if (!result.ok) {
        dbgWarning(D_WAAP_SERIALIZE) << "Failed to decompress chunk";
        return false;
    }

    if (result.output && result.num_output_bytes > 0) {
        decompressed_chunk.assign(
            reinterpret_cast<const char*>(result.output),
            reinterpret_cast<const char*>(result.output) + result.num_output_bytes
        );
        free(result.output);

        dbgTrace(D_WAAP_SERIALIZE) << "Decompressed chunk: " << compressed_chunk.size()
                                << " -> " << decompressed_chunk.size() << " bytes";

        // Yield after decompression to allow other routines to run
        YIELD_IF_POSSIBLE();
        return true;
    }

    // No output data yet (might need more input for compression algorithm)
    decompressed_chunk.clear();
    return true;
}
