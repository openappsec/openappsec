# Core Utilities

Small, broadly-used helpers in `core/`. Some are plain function namespaces
(filesystem, strings, regex, checksums); a couple are Singleton services
(encryptor). `Buffer` and the `utilities/` value helpers (`Flags`, `EnumArray`,
`Cache`, ...) are covered in [foundational-types.md](foundational-types.md) --
this doc covers the rest.

## NGEN:: helpers -- `agent_core_utilities.h`

`#include "agent_core_utilities.h"`. Namespaced free functions, no component
lookup. Reach for these instead of hand-rolling filesystem/string/regex code.

```cpp
namespace NGEN::Filesystem {
    bool exists(path); bool isDirectory(path);
    Maybe<std::vector<std::string>> getDirectoryFiles(path);
    bool makeDir(path, mode); bool makeDirRecursive(path, mode);
    bool deleteDirectory(path, bool delete_content); bool deleteFile(path);
    bool touchFile(path); std::string resolveFullPath(input);
    bool copyFile(src, dest, overwrite, mode); bool copyDirectory(src, dst);
    bool createFileWithContent(dest, content, overwrite, mode);
    std::string getFileName(path); std::string convertToHumanReadable(bytes);
}
namespace NGEN::Strings {
    std::string trim(s); removeLeadingWhitespaces(s); removeTrailingWhitespaces(s);
    std::string toLower(s); bool startsWith(s, prefix);
}
namespace NGEN::Regex {
    bool regexMatch(__FILE__, __LINE__, sample, [match,] regex);
    bool regexSearch(__FILE__, __LINE__, sample, match, regex);
    std::string regexReplace(__FILE__, __LINE__, sample, regex, replace);
}
```

Filesystem helpers return `bool`/`Maybe` rather than throwing -- check the
result. The `Regex` helpers take `__FILE__, __LINE__` so a malformed pattern or
throw is logged with the caller's location (boost::regex underneath).

## Connection keys -- `connkey.h`

`#include "connkey.h"` (from `services_sdk/utilities/`). Types for identifying a
connection by its 5-tuple. Reach for it when keying per-connection state (e.g.
the `Table<Key>` in the HTTP handler) or comparing/printing addresses.

- `IPAddr` -- an IPv4/IPv6 address wrapper (`IPType { UNINITIALIZED, V4, V6 }`),
  with `hash()`, `operator==`, `getType()`, and (unsafe) `getIPv4()/getIPv6()`.
- `PortNumber` (host-order `uint16_t`), `IPProto` (`uint8_t`).
- The full `ConnKey` (5-tuple) composes these; it is cereal-serializable (JSON)
  and hashable for use as a table key.

Note (memory discipline): on the WAAP mem-optim branch, prefer
sorted-vector / run-length structures over STL hash containers when keying by
connection -- see the WAAP memory guidance.

## Encryption -- `i_encryptor.h` (service)

A Singleton service (provided by the `Encryptor` component); consume with
`Singleton::Consume<I_Encryptor>::by<Self>()`. Reach for it to encode/obfuscate
or encrypt sensitive data at rest or in transit.

```cpp
// always available:
std::string base64Encode(in);   std::string base64Decode(in);
std::string obfuscateXor(in);   std::string obfuscateXorBase64(in);

// AES-256 (unless DISABLE_APPSEC_DATA_ENCRYPTION): all return Maybe<std::string>
encryptAES256obfuscateXorBase64(in);   decryptAES256obfuscateXorBase64(in);
aes256EncryptWithSizePad(in);          aes256DecryptWithSizePad(in);

// streaming, chunk-by-chunk (for large payloads):
createEncryptionContext();  encryptChunk(ctx, chunk, is_final);
createDecryptionContext();  decryptChunk(ctx, chunk, is_final);
encryptAES256obfuscateXorBase64Chunk(ctx, chunk, is_final);   // + decrypt variant
```

The AES-256 methods return `Maybe` because they can fail (bad input / cipher
error) -- check `.ok()`. The streaming `*Context` objects carry XOR offset and
base64 residual across chunks, so feed chunks in order and set `is_final=true`
on the last. Org policy: use approved AES-256 for sensitive data at rest; never
disable TLS verification or hardcode keys.
**Mock:** `mock_encryptor.h` (`MockEncryptor`).

## Compression -- `compression_utils.h` (C ABI)

`#include "compression_utils.h"`. A C-ABI streaming (de)compression utility
shared with the attachment code. Reach for it to compress/decompress HTTP bodies
(gzip/zlib/brotli) chunk-by-chunk.

```c
CompressionStream * initCompressionStream(void);
CompressionResult   compressData(stream, type, in_size, in, is_last_chunk);   // CompressionType: GZIP/ZLIB/BROTLI
DecompressionResult decompressData(stream, ...);                              // mirror
void                finiCompressionStream(stream);
```

`CompressionResult { int ok; uint32_t num_output_bytes; unsigned char *output; }`
-- check `ok`, read `num_output_bytes` from `output`. Logging is routed via
`setCompressionDebugFunction(level, fn)` so the C code reports through the host
logger. The streaming API means you initialize one stream per body and feed
chunks until `is_last_chunk`.

## Also in core (covered elsewhere)

| Helper | Where |
|--------|-------|
| `Buffer` (segmented bytes) | [foundational-types.md](foundational-types.md) |
| `Maybe<T,Err>` | [foundational-types.md](foundational-types.md) |
| `Flags`, `EnumArray`, `Cache`, `toString`, `scope_exit` | [foundational-types.md](foundational-types.md) / [interfaces-and-resources.md](interfaces-and-resources.md) |

## Key files

| File | Role |
|------|------|
| `core/include/services_sdk/utilities/agent_core_utilities.h` | `NGEN::Filesystem/Strings/Regex`. |
| `core/include/services_sdk/utilities/connkey.h` | `IPAddr`, `ConnKey`, port/proto types. |
| `core/include/services_sdk/interfaces/i_encryptor.h` | `I_Encryptor` (base64/XOR/AES-256, streaming). |
| `core/include/attachments/compression_utils.h` | C-ABI gzip/zlib/brotli streaming. |
