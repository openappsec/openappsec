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

#ifndef __PARSER_BASE_H__1106fa38
#define __PARSER_BASE_H__1106fa38

#include "DataTypes.h"
#include <string>
#include <stddef.h>

#define BUFFERED_RECEIVER_F_FIRST 0x01
#define BUFFERED_RECEIVER_F_LAST 0x02
#define BUFFERED_RECEIVER_F_BOTH (BUFFERED_RECEIVER_F_FIRST | BUFFERED_RECEIVER_F_LAST)
#define BUFFERED_RECEIVER_F_UNNAMED 0x04

#if (DISTRO_centos6)
// pre c++11 compiler doesn' support the "final" keyword
#define final
#else
// c++11 and beyond
#define final final
#endif

// Interface for receiver classes that accept full key/value pairs
struct IParserReceiver {
    virtual int onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth) = 0;
};

struct IParserReceiver2 {
    virtual void onKvt(const char *k, size_t k_len, const char *v, size_t v_len, const DataType &type) = 0;
    virtual void onStartMap() = 0;
    virtual void onMapKey(const char *k, size_t k_len) = 0;
    virtual void onEndMap() = 0;
    virtual void onStartArray() = 0;
    virtual void onEndArray() = 0;
    virtual void onEndOfData() = 0;
};

// Interface for receiver classes that can accept not only full key/value pairs, but also partial content
// Senders could do multiple calls to onKey() and onValue(), followed by call to onKvDone() that signals
// that both key and value data is ready.
// Alternatively, when they can, senders would do single call onKv(), bringing whole data in a single buffer,
// which is normally faster because this way senders could avoid unnecessary memory copying.
struct IParserStreamReceiver : public IParserReceiver {
    virtual int onKey(const char *k, size_t k_len) = 0;
    virtual int onValue(const char *v, size_t v_len) = 0;
    virtual int onKvDone() = 0;
    virtual void clear() = 0;
};

// This class acts as an adapter between senders that require IParserStreamReceiver and receivers
// that can only accept IParserReceiver (and do not want to cope with buffering).
// When onKv is received by an instance of BuferedReceiver -it will be transparently forwarded to destination
// (without memory copying).
// However, if BufferedReceiver instance accepts onKey, onValue calls, it buffers the data until onKvDone
// is called, at which point it passes buffered data to onKv callback of the final (non stream capable) receiver.
// TODO:: 1) when constructing this class, pass limits on key and value lengths as constructor parameters?
// TODO:: 2) add extra callback like "onFlush()" to both IParserStreamReceiver and its implementation
//           BufferedReceiver, which tells BufferedReceiver that it has last chance to copy data aside
//           before the underlying buffer is dead. Without receiving this call, BufferedStreamReceiver
//           can simply collect ptr+len pairs on buffer instead of copying stuff to m_key and m_value.
// Once onFlush() is received, the data must be collected from those spans, because the underlying buffer
// is going to be destroyed.
// Note that calls to onFlush() must be added to end of all parser functions before they loose control of their
// input buffer!
// However, this seems to be easy to implement: just call m_receiver.onFlush() before exiting parser's push()
// method, and we finally got zero-copy!
// Note that for optimization, the getAccumulatedKey() and getAccumulatedValue()
// should return pointers to the input buffer.
// This will in many cases cause sub-parsers to also work in zero-copy style too!
class BufferedReceiver : public IParserStreamReceiver {
public:
    BufferedReceiver(IParserReceiver &receiver, size_t parser_depth=0);
    virtual int onKey(const char *k, size_t k_len);
    virtual int onValue(const char *v, size_t v_len);
    virtual int onKvDone();
    virtual int onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth);
    virtual void clear();

    // Helper methods to access accumulated key and value (read-only)
    const std::string &getAccumulatedKey() const { return m_key; }
    const std::string &getAccumulatedValue() const { return m_value; }

private:
    IParserReceiver &m_receiver;
    int m_flags;
    // Accumulated key/value pair
    std::string m_key;
    std::string m_value;
    size_t m_parser_depth;

};

// Base class for various streaming parsers that accept data stream in multiple pieces through
// the push() calls, followed by the finish() call that signals end of the stream.
// Normally, the parsers will accept data, dissect/decode it and pass resulting data as
// stream of key/value pairs to a target that is either IParserReceiver or IParserStreamReceiver,
class ParserBase {
public:
    virtual ~ParserBase() {}
    virtual size_t push(const char *data, size_t data_len) = 0;
    virtual void finish() = 0; // TODO: I think this should return status of some sort, just like push()
    virtual const std::string &name() const = 0;
    virtual bool error() const = 0;
    virtual size_t depth() = 0;
    virtual void setRecursionFlag() { m_recursionFlag = true; }
    virtual void clearRecursionFlag() { m_recursionFlag = false; }
    virtual bool getRecursionFlag() const { return m_recursionFlag; }
private:
    bool m_recursionFlag = false;
};

template<typename _ParserType>
class BufferedParser : public ParserBase
{
public:
    template<typename ..._Args>
    explicit BufferedParser(IParserReceiver &receiver, size_t parser_depth, _Args... _args)
    :
        m_bufferedReceiver(receiver, parser_depth),
        // pass any extra arguments to specific parser's constructor
        m_parser(m_bufferedReceiver, parser_depth, _args...)
    {}
    virtual ~BufferedParser() {}
    virtual size_t push(const char *data, size_t data_len) { return m_parser.push(data, data_len); }
    virtual void finish() { m_parser.finish(); }
    virtual const std::string &name() const { return m_parser.name(); }
    virtual bool error() const { return m_parser.error(); }
    virtual size_t depth() { return m_parser.depth(); }
private:
    BufferedReceiver m_bufferedReceiver;
    _ParserType m_parser;
};

#endif // __PARSER_BASE_H___1106fa38
