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

#include "ParserXML.h"
#include "Waf2Util.h"
#include "debug.h"
#include <assert.h>
#include <boost/algorithm/string/case_conv.hpp>
#include <string>

USE_DEBUG_FLAG(D_WAAP_PARSER_XML);

const std::string ParserXML::m_parserName = "ParserXML";

void ParserXML::onStartElementNs(
    void* ctx,
    const xmlChar* localname,
    const xmlChar* prefix,
    const xmlChar* URI,
    int nb_namespaces,
    const xmlChar** namespaces,
    int nb_attributes,
    int nb_defaulted,
    const xmlChar** attributes)
{
    ParserXML* p = (ParserXML*)ctx;
    dbgTrace(D_WAAP_PARSER_XML) << "XML OPEN: '" << localname << "'";

    std::string aux_localname((const char*)localname, xmlStrlen(localname));

    boost::algorithm::to_lower(aux_localname);

    if (aux_localname == "script") {
        dbgTrace(D_WAAP_PARSER_XML) << "Failing parser on <script> tag";
        p->m_state = s_error;
    }

    p->m_key.push((const char*)localname, xmlStrlen(localname));

    int i;
    for (i = 0; i < nb_attributes; i++) {
        const xmlChar* attr_localname = attributes[i * 5 + 0];
        //const xmlChar *attr_prefix = attributes[i*5+1];
        //const xmlChar *attr_URI = attributes[i*5+2];
        const xmlChar* attr_value_begin = attributes[i * 5 + 3];
        const xmlChar* attr_value_end = attributes[i * 5 + 4];
        dbgTrace(D_WAAP_PARSER_XML) << "\tXML ATTR: elem='" << (char*)localname << "', " << attr_localname <<
            "='" << std::string((char*)attr_value_begin, (size_t)(attr_value_end - attr_value_begin)) << "'";
        p->m_key.push((const char*)attr_localname, xmlStrlen(attr_localname));
        if (p->m_receiver.onKv(
            p->m_key.c_str(),
            p->m_key.size(),
            (const char *)attr_value_begin,
            attr_value_end - attr_value_begin,
            BUFFERED_RECEIVER_F_BOTH,
            p->m_parser_depth
            ) != 0) {
            p->m_state = s_error;
        }
        p->m_key.pop("XML end attribute");
    }

    // before we add new tracking element to the stack for this new element,
    // set "children exists" flag to true for the parent element.
    if (!p->m_elemTrackStack.empty()) {
        p->m_elemTrackStack.back().hasChildren = true;
    }

    // when opening new element - start tracking its properties (internal text and existence of subelements)
    p->m_elemTrackStack.push_back(ElemTrackInfo());
}

void
ParserXML::onEndElementNs(
    void* ctx,
    const xmlChar* localname,
    const xmlChar* prefix,
    const xmlChar* URI)
{
    ParserXML* p = (ParserXML*)ctx;
    dbgTrace(D_WAAP_PARSER_XML) << "XML CLOSE: '" << localname << "'";

    if (p->m_elemTrackStack.empty()) {
        dbgWarning(D_WAAP_PARSER_XML) <<
            "XML closing tag and elem track stack is empty. This is probably sign of a bug!";
        return;
    }

    ElemTrackInfo& elemTrackInfo = p->m_elemTrackStack.back();

    // Usability optimization: only output kv pair for XML elements that had either sub children
    // and/or value within.
    // Those "wrapper elements" such as <wrapper><name>john</name><age>21</age></wrapper> only
    // contain sub elements. For these we don't emit kv pair.
    // However, for truly empty element such as <wrapper></wrapper>, or similar element with
    // text: <wrapper>some text</wrapper>, we do output a kv pair.
    bool isWrapperElement = elemTrackInfo.hasChildren && (elemTrackInfo.value.size() == 0);

    if (!isWrapperElement) {
        // Emit tag name as key
        if (p->m_receiver.onKey(p->m_key.c_str(), p->m_key.size()) != 0) {
            p->m_state = s_error;
        }

        if (p->m_receiver.onValue(elemTrackInfo.value.c_str(), elemTrackInfo.value.size()) != 0) {
            p->m_state = s_error;
        }

        if (p->m_receiver.onKvDone() != 0) {
            p->m_state = s_error; // error
        }
    }

    // when closing an element - pop its tracking info from the tracking stack
    p->m_elemTrackStack.pop_back();

    // Also, pop the element's name from m_key stack, so the key name always reflects
    // current depth within the elements tree
    p->m_key.pop("XML end element");
}

void ParserXML::onCharacters(void* ctx, const xmlChar* ch, int len) {
    ParserXML* p = (ParserXML*)ctx;

    if (p->m_elemTrackStack.empty()) {
        dbgWarning(D_WAAP_PARSER_XML) << "XML text and elem track stack is empty. This is probably sign of a bug!";
        return;
    }

    if ((ch == NULL) || (len == 0)) {
        dbgTrace(D_WAAP_PARSER_XML) << "Got empty XML text element. Ignoring.";
        return;
    }

    ElemTrackInfo& elemTrackInfo = p->m_elemTrackStack.back();

    dbgTrace(D_WAAP_PARSER_XML) << "XML TEXT: '[" << std::string((char*)ch, (size_t)len) << "]'";
    std::string val = std::string((char*)ch, (size_t)len);
    // trim isspace() characters around xml text chunks.
    // The chunks can occur multiple times within one value, when text value is intermixed with xml sub-tags.
    // for example, for XML source "<a>sta<b>zzz</b>rt</a>", the "a" tag will include two text
    // chunks "sta" and "rt"
    // which are concatenated here to form the word "start".
    // The trimming is done here to prevent false alarms on detection algorithm that sees
    // "\n" characters in the XML value.
    // Example of input that causes false alarm without this trim is (multiline XML):
    //  <xml><script>\nclean_xml_value '\n<\/script><\/xml>
    Waap::Util::trim(val);
    elemTrackInfo.value += val;
}

void
ParserXML::onEntityDeclaration(
    void* ctx,
    const xmlChar* name,
    int type,
    const xmlChar* publicId,
    const xmlChar* systmeid,
    xmlChar* content)
{
    dbgTrace(D_WAAP_PARSER_XML) << "ENTITY FOUND WITH VALUE: '" << (content ? (const char*)content : "null") << "'";

    ParserXML* p = (ParserXML*)ctx;
    std::string kw = "08a80340-06d3-11ea-9f87-0242ac11000f";

    if (p->m_receiver.onKey(p->m_key.c_str(), p->m_key.size()) != 0) {
        p->m_state = s_error;
    }

    if (p->m_receiver.onValue(kw.data(), kw.size()) != 0) {
        p->m_state = s_error;
    }

    if (p->m_receiver.onKvDone() != 0) {
        p->m_state = s_error; // error
    }
}

static void onError(void* ctx, const char* msg, ...) {
    static const size_t TMP_BUF_SIZE = 4096;
    char string[TMP_BUF_SIZE];
    va_list arg_ptr;

    va_start(arg_ptr, msg);
    vsnprintf(string, TMP_BUF_SIZE, msg, arg_ptr);
    va_end(arg_ptr);
    dbgTrace(D_WAAP_PARSER_XML) << "LIBXML (xml) onError: " << std::string(string);
}

ParserXML::ParserXML(IParserStreamReceiver &receiver, size_t parser_depth) :
    m_receiver(receiver),
    m_state(s_start),
    m_bufLen(0),
    m_key("xml_parser"),
    m_pushParserCtxPtr(NULL),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_XML)
        << "ParserXML::ParserXML() parser_depth="
        << parser_depth;
    // TODO:: is zeroing this really needed?
    memset(m_buf, 0, sizeof(m_buf));

    // Custom sax handler
    memset(&m_saxHandler, 0, sizeof(xmlSAXHandler));
    m_saxHandler.initialized = XML_SAX2_MAGIC;
    m_saxHandler.startElementNs = onStartElementNs;
    m_saxHandler.endElementNs = onEndElementNs;
    m_saxHandler.characters = onCharacters;
    m_saxHandler.entityDecl = onEntityDeclaration;
    m_saxHandler.error = onError;

    // Ugly: push first element into key (it will be ignored since we will never call
    // the "first()" method of this key within XML parser object.
    m_key.push("xml", 3);
}

ParserXML::~ParserXML() {
    // Cleanup XML
    dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::~ParserXML()";

    if (m_pushParserCtxPtr) {
        xmlFreeParserCtxt(m_pushParserCtxPtr);
    }
}

bool ParserXML::filterErrors(const xmlError *xmlError) {
    dbgDebug(D_WAAP_PARSER_XML) << "ParserXML::filterErrors(): xmlError " << xmlError->code << ": '" <<
        xmlError->message << "'";

    // Ignore specific error: "XML declaration allowed only at the start of the document".
    // This includes the case of "multiple XML declarations" we've seen sent by some SOAP clients.
    // The XML is still parsed because the parser is put into permissive mode with the XML_PARSE_RECOVER flag,
    // but even though it recovers and parses the XML correctly, the error code is still reported here.
    // Ignoring this error prevents the WAAP code from thinking the XML is "broken" and from scanning the XML
    // source as-is, in effect preventing false alarm on that XML source.
    if (xmlError->code == XML_ERR_RESERVED_XML_NAME || xmlError->code == XML_ERR_UNDECLARED_ENTITY) {
        dbgDebug(D_WAAP_PARSER_XML) << "ParserXML::filterErrors(): ignoring the '" << xmlError->code << ": " <<
            xmlError->message << "' xml parser error.";
        return false;
    }

    return true;
}

size_t ParserXML::push(const char* data, size_t data_len) {
    size_t i = 0;
    char c;

    if (data_len == 0) {
        dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): end of data signal! m_state=" << m_state;
        // Send zero-length chunk with "terminate" flag enabled to signify end-of-stream

        if (xmlParseChunk(m_pushParserCtxPtr, m_buf, 0, 1)) {
            auto xmlError = xmlCtxtGetLastError(m_pushParserCtxPtr);
            if (xmlError && filterErrors(xmlError)) {
                dbgDebug(D_WAAP_PARSER_XML) << "ParserXML::push(): xmlError: code=" << xmlError->code << ": '" <<
                    xmlError->message << "'";
                m_state = s_error; // error
                return -1;
            }
        }
        return m_bufLen;
    }
    int expected_buffer_len = FIRST_BUFFER_SIZE - 1;
    while (i < data_len) {
        c = data[i];

        switch (m_state) {
        case s_start:
            dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): s_start";
            m_state = s_accumulate_first_bytes;

            // fall through //
            CP_FALL_THROUGH;
        case s_accumulate_first_bytes:
            dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): s_accumulate_first_bytes. c='" << data[i] <<
                "'; m_bufLen=" << m_bufLen << "; i=" << i;
            m_buf[m_bufLen] = c;
            m_bufLen++;
            if (c == '?') {
                expected_buffer_len = FIRST_BUFFER_SIZE;
            }
            if (m_bufLen == expected_buffer_len) {
                m_state = s_start_parsing;
            }
            break;

        case s_start_parsing:
            dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): s_start_parsing. sending len=" << m_bufLen << ": '" <<
                std::string(m_buf, m_bufLen) << "'; i=" << i;
            // Create XML SAX (push parser) context
            // It is important to buffer at least first 4 bytes of input stream so libxml can determine text encoding!
            m_pushParserCtxPtr = xmlCreatePushParserCtxt(&m_saxHandler, this, m_buf, m_bufLen, NULL);

            // Enable "permissive mode" for XML SAX parser.
            // In this mode, the libxml parser doesn't stop on errors, but still reports them!
            xmlCtxtUseOptions(m_pushParserCtxPtr, XML_PARSE_RECOVER);

            m_state = s_parsing;

            // fall through //
            CP_FALL_THROUGH;
        case s_parsing:
            dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): s_parsing. sending len=" << (int)(data_len - i) <<
                ": '" << std::string(data + i, data_len - i) << "'; i=" << i;
            if (m_pushParserCtxPtr) {
                if (xmlParseChunk(m_pushParserCtxPtr, data + i, data_len - i, 0)) {
                    auto xmlError = xmlCtxtGetLastError(m_pushParserCtxPtr);
                    if (xmlError && filterErrors(xmlError)) {
                        dbgDebug(D_WAAP_PARSER_XML) << "ParserXML::push(): xmlError: code=" << xmlError->code <<
                            ": '" << xmlError->message << "'";
                        m_state = s_error; // error
                        return 0;
                    }
                }

                // success (whole buffer consumed)
                i = data_len - 1; // take into account ++i at the end of the state machine loop
            }
            break;
        case s_error:
            dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): s_error";
            return 0;
        }

        ++i;
    }

    dbgTrace(D_WAAP_PARSER_XML) << "ParserXML::push(): exiting with param(len)=" << data_len << ": i=" << i;
    return i;
}

void ParserXML::finish() {
    push(NULL, 0);
}

const std::string &
ParserXML::name() const {
    return m_parserName;
}

bool ParserXML::error() const {
    return m_state == s_error;
}
