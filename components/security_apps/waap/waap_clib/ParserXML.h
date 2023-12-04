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

#ifndef __PARSER_XML_H__5bf3b834
#define __PARSER_XML_H__5bf3b834

#include "ParserBase.h"
#include "KeyStack.h"
#include <libxml/xmlstring.h>
#include <libxml/xmlerror.h>
#include <libxml/parser.h>

#define FIRST_BUFFER_SIZE 5 // must buffer at least 4 first bytes to allow unicode autodetection (BOM).

class ParserXML : public ParserBase {
public:
    ParserXML(IParserStreamReceiver &receiver, size_t parser_depth);
    virtual ~ParserXML();
    size_t push(const char *data, size_t data_len);
    void finish();
    virtual const std::string &name() const;
    bool error() const;
    virtual size_t depth() { return (m_key.depth() > 0) ? m_key.depth()-1 : m_key.depth(); }
private:
    enum state {
        s_start,
        s_accumulate_first_bytes,
        s_start_parsing,
        s_parsing,
        s_error
    };

    // Information tracked per each element in current stack of tracked XML elements
    struct ElemTrackInfo {
        std::string value;
        bool hasChildren;
        ElemTrackInfo():hasChildren(false) {
            // when element is just opened - we still didn't see any children,
            // hence start with the "hasChildren" flag as false.
            // This flag will be enabled once we meet opening of the a subelement.
            // Also, we start from empty value string and gradually append to it each
            // time we receive next piece of text from XML parser.
            // The collected value is then emitted when element finishes.
        }
    };

    static void onStartElementNs(
        void *ctx,
        const xmlChar *localname,
        const xmlChar *prefix,
        const xmlChar *URI,
        int nb_namespaces,
        const xmlChar **namespaces,
        int nb_attributes,
        int nb_defaulted,
        const xmlChar **attributes);
    static void onEndElementNs(
        void* ctx,
        const xmlChar* localname,
        const xmlChar* prefix,
        const xmlChar* URI);
    static void onCharacters(
        void *ctx,
        const xmlChar *ch,
        int len);
    static void onEntityDeclaration(
            void* ctx,
            const xmlChar* name,
            int type,
            const xmlChar* publicId,
            const xmlChar* systmeid,
            xmlChar* content);

    // Filter out errors that should be ignored. Returns true if error should be treated,
    // false if an error should be ignored
    bool filterErrors(const xmlError *xmlError);

    IParserStreamReceiver &m_receiver;
    enum state m_state;
    // buffer first few bytes of stream (required before calling SAX parser for the first time)
    char m_buf[FIRST_BUFFER_SIZE];
    int m_bufLen;
    KeyStack m_key;
    std::vector<ElemTrackInfo> m_elemTrackStack;
    xmlSAXHandler m_saxHandler;
    xmlParserCtxtPtr m_pushParserCtxPtr;
    size_t m_parser_depth;
public:
    static const std::string m_parserName;
};

#endif // __PARSER_XML_H__5bf3b834
