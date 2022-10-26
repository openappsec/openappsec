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

#ifndef __I_HTTP_EVENT_IMPL_H__
#define __I_HTTP_EVENT_IMPL_H__

#ifndef __HTTP_INSPECTION_EVENTS_H__
#error i_http_event_impl.h should not be included directly!
#endif //__HTTP_INSPECTION_EVENTS_H__

#include <string>
#include <map>
#include <vector>

#include "debug.h"
#include "buffer.h"
#include "http_transaction_data.h"
#include "nginx_attachment_common.h"

USE_DEBUG_FLAG(D_HTTP_MANAGER);

using ModificationType = ngx_http_modification_type_e;
using ModificationPosition = ngx_http_cp_inject_pos_t;

static const ModificationPosition injection_pos_irrelevant = INJECT_POS_IRRELEVANT;

template <typename TMod>
class Modification
{
public:
    Modification(const TMod &mod, ModificationType mod_type)
            :
        Modification(mod, mod_type, injection_pos_irrelevant)
    {}

    Modification(const TMod &mod, ModificationType mod_type, ModificationPosition mod_position)
            :
        modification(mod),
        type(mod_type),
        position(mod_position)
    {
        dbgAssert(mod_type != ModificationType::APPEND || position == injection_pos_irrelevant)
            << "Injection position is not applicable to a modification of type \"Append\"";

        dbgAssert(mod_type != ModificationType::INJECT || position >= 0)
            << "Invalid injection position: must be non-negative. Position: "
            << position;
    }

    ModificationPosition getModificationPosition() const { return position; }
    ModificationType getModificationType() const { return type; }
    const TMod & getModification() const { return modification; }

private:
    TMod modification;
    ModificationType type;
    ModificationPosition position;
};

using ModifiedChunkIndex = int;
using ModificationBuffer = std::tuple<ModificationPosition, ModificationType, Buffer>;
using ModificationList = std::vector<ModificationBuffer>;
using EventModifications = std::pair<ModifiedChunkIndex, ModificationList>;

template <typename TMod>
class I_ModifiableContent
{
public:
    virtual Maybe<void> modify(const Modification<TMod> &mod) = 0;

    virtual ModificationList getModificationList() const = 0;

protected:
    virtual ~I_ModifiableContent() {}
};

using HeaderKey = std::string;
using HeaderModification = std::pair<std::pair<ModificationPosition, HeaderKey>, Buffer>;

class HttpHeaderModification : I_ModifiableContent<HeaderModification>
{
public:
    Maybe<void>
    appendHeader(const HeaderKey &key, const Buffer &value)
    {
        return modify(
            Modification<HeaderModification>(
                HeaderModification({ { injection_pos_irrelevant, key }, value }),
                ModificationType::APPEND
            )
        );
    }

    Maybe<void>
    injectValue(ModificationPosition position, const Buffer &data)
    {
        return modify(
            Modification<HeaderModification>(
                HeaderModification({ { position, HeaderKey() }, data }),
                ModificationType::INJECT,
                position
            )
        );
    }

    ModificationList
    getModificationList() const override
    {
        ModificationList modification_list;

        for (const auto &modification : headers_to_append) {
            modification_list.emplace_back(injection_pos_irrelevant, ModificationType::APPEND, modification.first);
            modification_list.emplace_back(injection_pos_irrelevant, ModificationType::APPEND, modification.second);
        }
        for (const auto &modification : header_injections) {
            modification_list.emplace_back(modification.first, ModificationType::INJECT, modification.second);
        }

        return modification_list;
    }

private:
    Maybe<void>
    modify(const Modification<HeaderModification> &mod) override
    {
        auto modification_type = mod.getModificationType();
        switch (modification_type) {
            case ModificationType::APPEND: {
                const HeaderKey &appended_header_key = mod.getModification().first.second;
                auto iterator = headers_to_append.find(appended_header_key);
                if (iterator != headers_to_append.end()) {
                    return
                        genError(
                            "Append modification with provided header key already exists. Header key: \"" +
                            appended_header_key +
                            "\""
                        );
                }

                headers_to_append.emplace(appended_header_key, mod.getModification().second);
                break;
            }
            case ModificationType::INJECT: {
                auto iterator = header_injections.find(mod.getModificationPosition());
                if (iterator != header_injections.end()) {
                    return genError("Inject modification with provided position already exists");
                }

                header_injections.emplace(mod.getModificationPosition(), mod.getModification().second);
                break;
            }
            case ModificationType::REPLACE: {
                // future support to pass new Content-Length
                dbgWarning(D_HTTP_MANAGER) << "Replace modification is not yet supported";
                break;
            }
            default:
                dbgAssert(false)
                    << "Unknown type of ModificationType: "
                    << static_cast<int>(modification_type);
        }

        return Maybe<void>();
    }

private:
    std::map<HeaderKey, Buffer> headers_to_append;
    std::map<ModificationPosition, Buffer> header_injections;
};

class HttpHeader
{
public:
    HttpHeader() = default;
    HttpHeader(const Buffer &_key, const Buffer &_value, uint8_t _header_index, bool _is_last_header = false)
            :
        key(_key),
        value(_value),
        is_last_header(_is_last_header),
        header_index(_header_index)
    {
    }

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <class Archive>
    void
    save(Archive &ar) const
    {
        ar(
            key,
            value,
            is_last_header,
            header_index
        );
    }

    template <class Archive>
    void
    load(Archive &ar)
    {
        ar(
            key,
            value,
            is_last_header,
            header_index
        );
    }
// LCOV_EXCL_STOP

    void
    print(std::ostream &out_stream) const
    {
        out_stream
            << "'"
            << std::dumpHex(key)
            << "': '"
            << std::dumpHex(value)
            << "' (Index: "
            << std::to_string(header_index)
            << ", Is last header: "
            << (is_last_header ? "True" : "False")
            << ")";
    }

    const Buffer & getKey() const { return key; }
    const Buffer & getValue() const { return value; }

    bool isLastHeader() const { return is_last_header; }
    uint8_t getHeaderIndex() const { return header_index; }

private:
    Buffer key;
    Buffer value;
    bool is_last_header = false;
    uint8_t header_index = 0;
};

using BodyModification = Buffer;
class HttpBodyModification : I_ModifiableContent<BodyModification>
{
public:
    Maybe<void>
    inject(ModificationPosition position, const Buffer &data)
    {
        return modify(
            Modification<BodyModification>(
                std::move(data),
                ModificationType::INJECT,
                position
            )
        );
    }

    ModificationList
    getModificationList() const override
    {
        ModificationList injected_data;
        for (const auto &injection : modifications) {
            auto injection_buffer = injection.second;
            injected_data.emplace_back(injection.first, ModificationType::INJECT, injection_buffer);
        }
        return injected_data;
    }

private:
    Maybe<void>
    modify(const Modification<BodyModification> &mod) override
    {
        if (modifications.find(mod.getModificationPosition()) != modifications.end()) {
            return genError("Modification at the provided index already exists");
        }
        modifications[mod.getModificationPosition()] = mod.getModification();
        return Maybe<void>();
    }

    std::map<ModificationPosition, Buffer> modifications;
};

class HttpBody
{
public:
    HttpBody()
            :
        data(),
        previous_chunked_data(),
        is_last_chunk(false),
        body_chunk_index(0)
    {}

    HttpBody(const Buffer &body_data, bool _is_last_chunk, uint8_t _body_chunk_index)
            :
        data(body_data),
        previous_chunked_data(),
        is_last_chunk(_is_last_chunk),
        body_chunk_index(_body_chunk_index)
    {}

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <class Archive>
    void
    save(Archive &ar) const
    {
        ar(
            data,
            previous_chunked_data,
            is_last_chunk,
            body_chunk_index
        );
    }

    template <class Archive>
    void
    load(Archive &ar)
    {
        ar(
            data,
            previous_chunked_data,
            is_last_chunk,
            body_chunk_index
        );
    }
// LCOV_EXCL_STOP

    void
    print(std::ostream &out_stream) const
    {
        out_stream
            << "'"
            << std::dumpHex(data)
            << "' (Index: "
            << std::to_string(body_chunk_index)
            << ", Is last chunk: "
            << (is_last_chunk ? "True" : "False")
            << ")";
    }

    const Buffer & getData() const { return data; }
    const Buffer & getPreviousChunkedData() const { return previous_chunked_data; }
    void setPreviousChunkedData(const Buffer &prev_body_data) { previous_chunked_data = prev_body_data; }

    bool isLastChunk() const { return is_last_chunk; }
    uint8_t getBodyChunkIndex() const { return body_chunk_index; }

private:
    Buffer data;
    Buffer previous_chunked_data;
    bool is_last_chunk;
    uint8_t body_chunk_index;
};

class EventVerdict
{
public:
    EventVerdict() = default;

    EventVerdict(ngx_http_cp_verdict_e event_verdict) : modifications(), verdict(event_verdict) {}

    EventVerdict(const ModificationList &mods) : modifications(mods) {}

    EventVerdict(const ModificationList &mods, ngx_http_cp_verdict_e event_verdict) :
        modifications(mods),
        verdict(event_verdict)
    {}

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <typename T> void serialize(T &ar, uint) { ar(verdict); }
// LCOV_EXCL_STOP

    const ModificationList & getModifications() const { return modifications; }
    ngx_http_cp_verdict_e getVerdict() const { return verdict; }

private:
    ModificationList modifications;
    ngx_http_cp_verdict_e verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
};

#endif // __I_HTTP_EVENT_IMPL_H__
