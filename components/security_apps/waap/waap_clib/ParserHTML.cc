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

#include "ParserHTML.h"
#include "Waf2Util.h"
#include "debug.h"
#include <assert.h>

USE_DEBUG_FLAG(D_WAAP_PARSER_HTML);

const std::string ParserHTML::m_parserName = "ParserHTML";

void ParserHTML::onStartElement(
    void* ctx,
    const xmlChar* localname,
    const xmlChar** attributes)
{
    ParserHTML* p = (ParserHTML*)ctx;
    dbgTrace(D_WAAP_PARSER_HTML) << "HTML OPEN: '" << localname << "'";

    p->m_key.push((const char*)localname, xmlStrlen(localname));

    if (attributes != NULL) {
        int i;
        for (i = 0; attributes[i*2]; i++) {
            const xmlChar* attr_localname = attributes[i * 2 + 0];
            const xmlChar* attr_value = attributes[i * 2 + 1];
            if (attr_value == NULL) {
                attr_value = (const xmlChar*)"";
            }

            dbgTrace(D_WAAP_PARSER_HTML)
                << "\tHTML ATTR: elem='"
                << (char *)localname
                << "', "
                << attr_localname
                << "='"
                << std::string((char *)attr_value)
                << "'";
            p->m_key.push((const char *)attr_localname, xmlStrlen(attr_localname));
            if (p->m_receiver.onKv(
                    p->m_key.first().c_str(),
                    p->m_key.first().size(),
                    (const char *)attr_value,
                    strlen((const char *)attr_value),
                    BUFFERED_RECEIVER_F_BOTH,
                    p->m_parser_depth
                ) != 0) {
                p->m_state = s_error;
            }
            p->m_key.pop("HTML end attribute");
        }
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
ParserHTML::onEndElement(
    void* ctx,
    const xmlChar* localname)
{
    ParserHTML* p = (ParserHTML*)ctx;
    dbgTrace(D_WAAP_PARSER_HTML) << "HTML CLOSE: '" << localname << "'";

    if (p->m_elemTrackStack.empty()) {
        dbgWarning(D_WAAP_PARSER_HTML)
            << "HTML closing tag and elem track stack is empty. This is probably sign of a bug!";
        return;
    }

    ElemTrackInfo& elemTrackInfo = p->m_elemTrackStack.back();

    // Usability optimization: only output kv pair for HTML elements that had either sub children
    // and/or value within.
    // Those "wrapper elements" such as <wrapper><name>john</name><age>21</age></wrapper> only
    // contain sub elements. For these we don't emit kv pair.
    // However, for truly empty element such as <wrapper></wrapper>, or similar element with
    // text: <wrapper>some text</wrapper>, we do output a kv pair.
    bool isWrapperElement = elemTrackInfo.hasChildren && (elemTrackInfo.value.size() == 0);

    if (!isWrapperElement) {
        // Emit tag name as key
        if (p->m_receiver.onKey(p->m_key.first().c_str(), p->m_key.first().size()) != 0) {
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
    p->m_key.pop("HTML end element");
}

void
ParserHTML::onCharacters(void *ctx, const xmlChar *ch, int len)
{
    ParserHTML *p = (ParserHTML *)ctx;

    if (p->m_elemTrackStack.empty()) {
        dbgWarning(D_WAAP_PARSER_HTML) << "HTML text and elem track stack is empty. This is probably sign of a bug!";
        return;
    }

    if ((ch == NULL) || (len == 0)) {
        dbgTrace(D_WAAP_PARSER_HTML) << "Got empty HTML text element. Ignoring.";
        return;
    }

    ElemTrackInfo& elemTrackInfo = p->m_elemTrackStack.back();

    dbgTrace(D_WAAP_PARSER_HTML) << "HTML TEXT: '[" << std::string((char*)ch, (size_t)len) << "]'";
    std::string val = std::string((char*)ch, (size_t)len);
    // trim isspace() characters around html text chunks.
    // The chunks can occur multiple times within one value, when text value is intermixed with html sub-tags.
    // for example, for HTML source "<a>sta<b>zzz</b>rt</a>", the "a" tag will include two text
    // chunks "sta" and "rt"
    // which are concatenated here to form the word "start".
    // The trimming is done here to prevent false alarms on detection algorithm that sees
    // "\n" characters in the HTML value.
    // Example of input that causes false alarm without this trim is (multiline HTML):
    //  <html><script>\nclean_html_value '\n<\/script><\/html>
    Waap::Util::trim(val);
    elemTrackInfo.value += val;
}

static void
onError(void *ctx, const char *msg, ...)
{
    static const size_t TMP_BUF_SIZE = 4096;
    char string[TMP_BUF_SIZE];
    va_list arg_ptr;

    va_start(arg_ptr, msg);
    vsnprintf(string, TMP_BUF_SIZE, msg, arg_ptr);
    va_end(arg_ptr);
    dbgTrace(D_WAAP_PARSER_HTML) << "LIBXML (html) onError: " << std::string(string);
}

ParserHTML::ParserHTML(IParserStreamReceiver &receiver, size_t parser_depth) :
    m_receiver(receiver),
    m_state(s_start),
    m_bufLen(0),
    m_key("html_parser"),
    m_pushParserCtxPtr(NULL),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_HTML)
        << "ParserHTML::ParserHTML()"
        << "parser_depth="
        << parser_depth;

    // TODO:: is zeroing this really needed?
    memset(m_buf, 0, sizeof(m_buf));

    // Custom sax handler
    memset(&m_saxHandler, 0, sizeof(htmlSAXHandler));
    m_saxHandler.startElement = onStartElement;
    m_saxHandler.endElement = onEndElement;
    m_saxHandler.characters = onCharacters;
    m_saxHandler.error = onError;

    // Register "dummy" tag to receive any text
    m_elemTrackStack.push_back(ElemTrackInfo());

    // Ugly: push first element into key (it will be ignored since we will never call
    // the "first()" method of this key within HTML parser object.
    m_key.push("html", 4);
}

ParserHTML::~ParserHTML()
{
    // Cleanup HTML
    dbgTrace(D_WAAP_PARSER_HTML) << "ParserHTML::~ParserHTML()";

    if (m_pushParserCtxPtr) {
        htmlFreeParserCtxt(m_pushParserCtxPtr);
    }
}

bool
ParserHTML::filterErrors(const xmlError *xmlError)
{
    dbgDebug(D_WAAP_PARSER_HTML)
        << "ParserHTML::filterErrors(): xmlError "
        << xmlError->code
        << ": '"
        << xmlError->message
        << "'";

    // Ignore specific error: "HTML declaration allowed only at the start of the document".
    // This includes the case of "multiple HTML declarations" we've seen sent by some SOAP clients.
    // The HTML is still parsed because the parser is put into permissive mode with the HTML_PARSE_RECOVER flag,
    // but even though it recovers and parses the HTML correctly, the error code is still reported here.
    // Ignoring this error prevents the WAAP code from thinking the HTML is "broken" and from scanning the HTML
    // source as-is, in effect preventing false alarm on that HTML source.
    if (xmlError->code == XML_ERR_RESERVED_XML_NAME || xmlError->code == XML_ERR_UNDECLARED_ENTITY) {
        dbgDebug(D_WAAP_PARSER_HTML)
            << "ParserHTML::filterErrors(): ignoring the '"
            << xmlError->code
            << ": "
            << xmlError->message
            << "' html parser error.";
        return false;
    }

    return true;
}

size_t
ParserHTML::push(const char *data, size_t data_len)
{
    size_t i = 0;
    char c;

    if (data_len == 0) {
        dbgTrace(D_WAAP_PARSER_HTML) << "ParserHTML::push(): end of data signal! m_state=" << m_state;
        // Send zero-length chunk with "terminate" flag enabled to signify end-of-stream

        if (htmlParseChunk(m_pushParserCtxPtr, m_buf, 0, 1)) {
            auto xmlError = xmlCtxtGetLastError(m_pushParserCtxPtr);
            if (xmlError && filterErrors(xmlError)) {
                dbgDebug(D_WAAP_PARSER_HTML)
                    << "ParserHTML::push(): xmlError: code="
                    << xmlError->code
                    << ": '"
                    << xmlError->message
                    << "'";
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
            dbgTrace(D_WAAP_PARSER_HTML) << "ParserHTML::push(): s_start";
            m_state = s_accumulate_first_bytes;

            // fall through //
            CP_FALL_THROUGH;
        case s_accumulate_first_bytes:
                dbgTrace(D_WAAP_PARSER_HTML)
                    << "ParserHTML::push(): s_accumulate_first_bytes. c='"
                    << data[i]
                    << "'; m_bufLen="
                    << m_bufLen
                    << "; i="
                    << i;
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
                dbgTrace(D_WAAP_PARSER_HTML)
                    << "ParserHTML::push(): s_start_parsing. sending len="
                    << m_bufLen
                    << ": '"
                    << std::string(m_buf, m_bufLen)
                    << "'; i="
                    << i;
                // Create HTML SAX (push parser) context
                // It is important to buffer at least first 4 bytes of input stream so libxml can determine text
                // encoding!
                m_pushParserCtxPtr =
                    htmlCreatePushParserCtxt(&m_saxHandler, this, m_buf, m_bufLen, NULL, XML_CHAR_ENCODING_UTF8);

            // Enable "permissive mode" for HTML SAX parser.
            // In this mode, the libxml parser doesn't stop on errors, but still reports them!
            htmlCtxtUseOptions(m_pushParserCtxPtr, HTML_PARSE_RECOVER);

            m_state = s_parsing;

            // fall through //
            CP_FALL_THROUGH;
        case s_parsing:
                dbgTrace(D_WAAP_PARSER_HTML)
                    << "ParserHTML::push(): s_parsing. sending len="
                    << (int)(data_len - i)
                    << ": '"
                    << std::string(data + i, data_len - i)
                    << "'; i="
                    << i;
            if (m_pushParserCtxPtr) {
                if (htmlParseChunk(m_pushParserCtxPtr, data + i, data_len - i, 0)) {
                    auto xmlError = xmlCtxtGetLastError(m_pushParserCtxPtr);
                    if (xmlError && filterErrors(xmlError)) {
                            dbgDebug(D_WAAP_PARSER_HTML)
                                << "ParserHTML::push(): xmlError: code="
                                << xmlError->code
                                << ": '"
                                << xmlError->message
                                << "'";
                        m_state = s_error; // error
                        return 0;
                    }
                }

                // success (whole buffer consumed)
                i = data_len - 1; // take into account ++i at the end of the state machine loop
            }
            break;
        case s_error:
            dbgTrace(D_WAAP_PARSER_HTML) << "ParserHTML::push(): s_error";
            return 0;
        }

        ++i;
    }

    dbgTrace(D_WAAP_PARSER_HTML) << "ParserHTML::push(): exiting with param(len)=" << data_len << ": i=" << i;
    return i;
}

void
ParserHTML::finish()
{
    push(NULL, 0);
}

const std::string &
ParserHTML::name() const
{
    return m_parserName;
}

bool
ParserHTML::error() const
{
    return m_state == s_error;
}
