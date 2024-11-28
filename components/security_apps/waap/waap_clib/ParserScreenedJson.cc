#include "ParserScreenedJson.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_SCREENED_JSON);

const std::string ParserScreenedJson::m_parserName = "ParserScreenedJson";

ParserScreenedJson::ParserScreenedJson(IParserStreamReceiver &receiver, size_t parser_depth) :
    m_receiver(receiver),
    m_state(s_start),
    m_unscreenedLen(0),
    m_leftoverLen(0),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
        << "parser_depth="
        << parser_depth;

    memset(m_unscreened, 0, sizeof(m_unscreened));
}

ParserScreenedJson::~ParserScreenedJson()
{}

size_t
ParserScreenedJson::push(const char *buf, size_t len)
{
    size_t i = 0;
    char c;

    dbgTrace(D_WAAP_PARSER_SCREENED_JSON) << "ParserScreenedJson::push(): starting (len=" << len << ")";

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_SCREENED_JSON) << "ParserScreenedJson::push(): end of data signal! m_state=" << m_state;
        // flush unescaped data collected (if any)
        if (m_leftoverLen > 0) {
            // No need any processing for leftover data - last char must be doublequote, else - error
            m_state = s_error;
            dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
                << "ParserScreenedJson::push(): end of data and leftover detected m_state="
                << m_state;
            return i;
        }
        dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
            << "ParserScreenedJson::push(): s_value, pushing m_unscreened = "
            << m_unscreened
            << ", m_leftoverLen = "
            << m_leftoverLen
            << ", m_unscreenedLen = "
            << m_unscreenedLen;

        if (m_receiver.onKey("json_unscreened", 15) != 0) {
            m_state = s_error;
            return i;
        }

        if (m_receiver.onValue(m_unscreened, m_unscreenedLen) != 0) {
            m_state = s_error;
            return i;
        }

        if (m_receiver.onKvDone() != 0)
        {
            m_state = s_error;
            return i;
        }
        return 0;
    }

    while (i < len)
    {
        c = buf[i];

        dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
            << "ParserScreenedJson::push(): state="
            << m_state
            << "; c='"
            << c
            << "'"
            << "; i="
            << i
            << ", m_leftoverLen = "
            << m_leftoverLen
            << ", m_unscreenedLen = "
            << m_unscreenedLen
            << ", m_unscreened = "
            << m_unscreened;

        switch (m_state)
        {
            case s_start:
            {
                dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
                    << "ParserScreenedJson::push(): s_start";
                m_state = s_value;

                // fallthrough  not required, removing 1st doublequote, it denoted by regex //
                //CP_FALL_THROUGH;
                break;
            }
            case s_value:
            {
                if (c == '\\') {
                    if (m_leftoverLen > 0) {
                        m_unscreened[m_unscreenedLen] = '\\';
                        m_leftoverLen = 0;
                        m_unscreenedLen++;
                    } else {
                        m_leftoverLen++;
                    }
                } else  if (c =='\"') {
                    if (m_leftoverLen > 0) {
                        m_unscreened[m_unscreenedLen] = '\"';
                        m_unscreenedLen++;
                        if (m_leftoverLen > 0) {
                            m_leftoverLen = 0;
                        }
                    }
                } else {
                    if (m_leftoverLen > 0) {
                        m_unscreened[m_unscreenedLen] = '\\';
                        m_unscreenedLen++;
                        m_leftoverLen = 0;
                    }
                    m_unscreened[m_unscreenedLen] = c;
                    m_unscreenedLen++;
                }
                if (m_unscreenedLen >= MAX_UNSCREENED_JSON_SIZE) {
                    if (m_receiver.onKey("json_unscreened", 15) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
                    << "ParserScreenedJson::push(): s_value, pushing m_unscreened = "
                    << m_unscreened
                    << ", m_leftoverLen = "
                    << m_leftoverLen
                    << ", m_unscreenedLen = "
                    << m_unscreenedLen;
                    if (m_receiver.onValue(m_unscreened, m_unscreenedLen) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    m_unscreenedLen = 0;
                }
            break;
            }
            case s_error:
            {
                dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
                    << "ParserScreenedJson::push(): s_error";
                return 0;
            }
            default:
            {
                dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
                    << "ParserScreenedJson::push(): JSON parser unrecoverable error";
                m_state = s_error;
                return 0;
            }
        }
        ++i;
    }

    dbgTrace(D_WAAP_PARSER_SCREENED_JSON)
        << "ParserScreenedJson::push(): finished: len="
        << len;
    return len;
}

void
ParserScreenedJson::finish()
{
    push(NULL, 0);
}

const std::string &
ParserScreenedJson::name() const
{
    return m_parserName;
}

bool
ParserScreenedJson::error() const
{
    return m_state == s_error;
}
