#include "Waf2Util.h"
#include "Waf2Regex.h"
#include <string>
#include "debug.h"

namespace Waap {
namespace Util {
using namespace std;

static const char *trueString = "true";
static const size_t trueStringLen = strlen(trueString);
static const char *falseString = "false";
static const size_t falseStringLen = strlen(falseString);
static const char *nullString = "null";
static const size_t nullStringLen = strlen(nullString);
static const char *quoteString = "%22";
static const size_t quoteStringLen = strlen(quoteString);

int
isAlignedPrefix(
    const char *sample,
    const size_t sample_len,
    const char *buffer,
    const size_t buffer_len)
{
    size_t lookup_len = 0;
    if (buffer_len < sample_len) {
        lookup_len = buffer_len;
    } else {
        lookup_len = sample_len;
    }
    if (strncmp(sample, buffer, lookup_len) == 0) {
        return lookup_len;
    }
    return -1;
}

int
isBoolean(
    const char *buffer,
    const size_t buffer_len)
{
    int status;

    status = isAlignedPrefix(trueString, trueStringLen, buffer, buffer_len);
    if (status >= 0) {
        return status;
    }
    status = isAlignedPrefix(falseString, falseStringLen, buffer, buffer_len);
    if (status >= 0) {
        return status;
    }
    status = isAlignedPrefix(nullString, nullStringLen, buffer, buffer_len);
    if (status >= 0) {
        return status;
    }
    return -1;
}

bool
isValidExponent(
    const char * buffer,
    const size_t buffer_len,
    size_t *i)
{
    if (buffer_len == *i + 1) {
        return true; // e or E is the last char in buffer
    }
    if (*i + 1 < buffer_len && (isdigit(buffer[*i + 1]) || (buffer[*i + 1] == '+' || buffer[*i + 1] == '-'))) {
        (*i) += 1;
        if (isdigit(buffer[*i + 1])) {
            return true;
        }
    } else {
        return false;
    }
    return false;
}

bool
isObjectStart(const char c, int *object_count)
{
    if (c == '{') {
        (*object_count)++;
        return true;
    }
    return false;
}

bool
isObjectEnd(const char c, int *object_count)
{
    if (c == '}') {
        (*object_count)--;
        return true;
    }
    return false;
}

bool
isArrayStart(const char c, int *array_count)
{
    if (c == '[') {
        (*array_count)++;
        return true;
    }
    return false;
}

bool
isArrayEnd(const char c, int *array_count)
{
    if (c == ']') {
        (*array_count)--;
        return true;
    }
    return false;
}

bool
isValidJson(const std::string &input)
{
    static const size_t MAX_JSON_INSPECT_SIZE = 16;

    enum state
    {
        S_START,          // 0
        S_OBJECT_START,   // 1
        S_OBJECT_END,     // 2
        S_ARRAY_START,    // 3
        S_ARRAY_END,      // 4
        S_NUMBER,         // 5
        S_NUMBER_END,     // 6
        S_STRING_START,   // 7
        S_STRING_BODY,    // 8
        S_STRING_END,     // 9
        S_VARIABLE_START, // 10
        S_VARIABLE_BODY,  // 11
        S_VARIABLE_END,   // 12
        S_COMMA,          // 13
        S_COLON,          // 14
        S_BOOLEAN,        // 15
        S_ERROR,          // 16
        S_END             // 17
    };

    state m_state;
    bool encoded = false;
    size_t i = 0;
    char c;
    const char *buf = input.c_str();
    size_t len = input.length();
    int array_count = 0;
    int object_count = 0;
    int status;
    if (len < 2) {
        return false;
    }

    m_state = S_START;
    while (i < len && i < MAX_JSON_INSPECT_SIZE) {
        c = buf[i];
        if (c == 0x0) { // UTF16 to UTF8 support
            i++;
            continue;
        }
        switch (m_state) {
            case S_START:
                if (isObjectStart(c, &object_count)) {
                    m_state = S_OBJECT_START;
                    break;
                }
                if (isArrayStart(c, &array_count)) {
                    m_state = S_ARRAY_START;
                    break;
                }
                m_state = S_ERROR;
                break; // S_START

            case S_OBJECT_START:
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                if (c == '\"') {
                    m_state = S_VARIABLE_START;
                    break;
                }
                if (isspace(c)) {
                    break;
                }
                status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                if (status >= 0) {
                    m_state = S_VARIABLE_START;
                    encoded = true;
                    i += status - 1;
                    break;
                }
                m_state = S_ERROR;
                break; // object_start

            case S_ARRAY_START:
                if (isObjectStart(c, &object_count)) {
                    m_state = S_OBJECT_START;
                    break;
                }
                if (isArrayStart(c, &array_count)) {
                    // keep state unchanged
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isdigit(c)) {
                    m_state = S_NUMBER;
                    break;
                }
                if (c == '-') {
                    if (i + 1 == len) { // End of buffer case
                        m_state = S_NUMBER;
                        break;
                    }
                    if (i + 1 < len && isdigit(buf[i + 1])) {
                        m_state = S_NUMBER;
                        i++;
                        break;
                    }
                    m_state = S_ERROR;
                    break;
                }
                if (isspace(c)) {
                    break;
                }
                if (c == '\"') {
                    m_state = S_STRING_START;
                    break;
                }
                status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                if (status >= 0) {
                    m_state = S_STRING_START;
                    encoded = true;
                    i += status - 1;
                    break;
                } else {
                    m_state = S_ERROR;
                }
                status = isBoolean(buf + i, len - i);
                if (status >= 0) {
                    m_state = S_BOOLEAN;
                    i += status - 1;
                    break;
                }
                m_state = S_ERROR;
                break; // array_start

            case S_OBJECT_END:
                if (isspace(c)) {
                    break;
                }
                if (c == ',') {
                    m_state = S_COMMA;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                if (isArrayStart(c, &array_count)) { // nJSON support but contradicts to definition of json.org
                    m_state = S_ARRAY_START;
                    break;
                }
                if (isObjectStart(c, &object_count)) { // nJSON support but contradicts to definition of json.org
                    m_state = S_OBJECT_START;
                    break;
                }
                m_state = S_ERROR;
                break; // S_OBJECT_END

            case S_ARRAY_END:
                if (isspace(c)) {
                    break;
                }
                if (c == ',') {
                    m_state = S_COMMA;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                if (isArrayStart(c, &array_count)) { // nJSON support but contradicts to definition of json.org
                    m_state = S_ARRAY_START;
                    break;
                }
                if (isObjectStart(c, &object_count)) { // nJSON support but contradicts to definition of json.org
                    m_state = S_OBJECT_START;
                    break;
                }
                m_state = S_ERROR;
                break; // S_ARRAY_END

            case S_NUMBER:
                if (isdigit(c)) {
                    break;
                }
                if (c == '.') {
                    if (i + 1 == len) { // End of buffer case
                        m_state = S_NUMBER;
                        break;
                    }
                    if (i + 1 < len && isdigit(buf[i + 1])) {
                        m_state = S_NUMBER;
                        i++;
                        break;
                    }
                    m_state = S_ERROR;
                    break;
                }
                if (c == 'e' || c == 'E') {
                    if (isValidExponent(buf, len, &i)) {
                        m_state = S_NUMBER;
                        break;
                    }
                    m_state = S_ERROR;
                    break;
                }
                if (isspace(c)) {
                    m_state = S_NUMBER_END;
                    break;
                }
                if (c == ',') {
                    m_state = S_COMMA;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                m_state = S_ERROR;
                break; // S_NUMBER

            case S_NUMBER_END:
                if (isspace(c)) {
                    break;
                }
                if (c == ',') {
                    m_state = S_COMMA;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                m_state = S_ERROR;
                break; // S_NUMBER_END

            case S_STRING_START:
                if (c == '\"') {
                    m_state = S_STRING_END;
                    break;
                }
                if (encoded) { // url_encoded quote
                    status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                    if (status >= 0) {
                        m_state = S_STRING_END;
                        encoded = true;
                        i += status - 1;
                        break;
                    } else {
                        m_state = S_ERROR;
                    }
                }
                m_state = S_STRING_BODY;
                break; // S_STRING_START

            case S_STRING_BODY:
                if (c == '\"') {
                    if (buf[i - 1] == '\\' && buf[i - 2] != '\\') {
                        m_state = S_STRING_BODY;
                        break;
                    } else {
                        m_state = S_STRING_END;
                        break;
                    }
                }
                if (encoded) { // url_encoded quote
                    status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                    if (status >= 0) {
                        m_state = S_STRING_END;
                        encoded = true;
                        i += status - 1;
                        break;
                    } else {
                        m_state = S_ERROR;
                    }
                }
                m_state = S_STRING_BODY;
                break; // S_STRING_BODY;

            case S_STRING_END:
                if (isspace(c)) {
                    break;
                }
                if (c == ',') {
                    m_state = S_COMMA;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                if (c == ':') {
                    m_state = S_COLON;
                    break;
                }
                m_state = S_ERROR;
                break; // s_sting_end

            case S_VARIABLE_START:
                if (c == '\"') {
                    m_state = S_VARIABLE_END;
                    break;
                }
                if (encoded) { // url_encoded quote
                    status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                    if (status >= 0) {
                        m_state = S_VARIABLE_END;
                        encoded = true;
                        i += status - 1;
                        break;
                    } else {
                        m_state = S_ERROR;
                    }
                }
                m_state = S_VARIABLE_BODY;
                break; // S_VARIABLE_START

            case S_VARIABLE_BODY:
                if (c == '\"') {
                    if (buf[i - 1] == '\\' && buf[i - 2] != '\\') {
                        m_state = S_VARIABLE_BODY;
                        break;
                    } else {
                        m_state = S_VARIABLE_END;
                        break;
                    }
                }
                if (encoded) { // url_encoded quote
                    status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                    if (status >= 0) {
                        m_state = S_VARIABLE_END;
                        encoded = true;
                        i += status - 1;
                        break;
                    } else {
                        m_state = S_ERROR;
                    }
                }
                m_state = S_VARIABLE_BODY;
                break; // S_VARIABLE_BODY

            case S_VARIABLE_END:
                if (isspace(c)) {
                    break;
                }
                if (c == ':') {
                    m_state = S_COLON;
                    break;
                }
                m_state = S_ERROR;
                break; // S_VARIABLE_END

            case S_COMMA:
                if (isObjectStart(c, &object_count)) {
                    m_state = S_OBJECT_START;
                    break;
                }
                if (isArrayStart(c, &array_count)) {
                    m_state = S_ARRAY_START;
                    break;
                }
                if (isdigit(c)) {
                    m_state = S_NUMBER;
                    break;
                }
                if (c == '-') {
                    if (i + 1 == len) { // End of buffer case
                        m_state = S_NUMBER;
                        break;
                    }
                    if (i + 1 < len && isdigit(buf[i + 1])) {
                        m_state = S_NUMBER;
                        i++;
                        break;
                    }
                    m_state = S_ERROR;
                    break;
                }
                if (isspace(c)) {
                    break;
                }
                if (c == '\"') {
                    m_state = S_STRING_START;
                    break;
                }
                status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                if (status >= 0) {
                    m_state = S_STRING_START;
                    encoded = true;
                    i += status - 1;
                    break;
                } else {
                    m_state = S_ERROR;
                }
                status = isBoolean(buf + i, len - i);
                if (status >= 0) {
                    m_state = S_BOOLEAN;
                    i += status - 1;
                    break;
                }
                m_state = S_ERROR;
                break; // S_COMMA

            case S_COLON:
                if (isObjectStart(c, &object_count)) {
                    m_state = S_OBJECT_START;
                    break;
                }
                if (isArrayStart(c, &array_count)) {
                    m_state = S_ARRAY_START;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isdigit(c)) {
                    m_state = S_NUMBER;
                    break;
                }
                if (c == '-') {
                    if (i + 1 == len) { // End of buffer case
                        m_state = S_NUMBER;
                        break;
                    }
                    if (i + 1 < len && isdigit(buf[i + 1])) {
                        m_state = S_NUMBER;
                        i++;
                        break;
                    }
                    m_state = S_ERROR;
                    break;
                }
                if (isspace(c)) {
                    break;
                }
                if (c == '\"') {
                    m_state = S_STRING_START;
                    break;
                }
                status = isAlignedPrefix(quoteString, quoteStringLen, buf + i, len - i);
                if (status >= 0) {
                    m_state = S_STRING_START;
                    encoded = true;
                    i += status - 1;
                    break;
                } else {
                    m_state = S_ERROR;
                }
                status = isBoolean(buf + i, len - i);
                if (status >= 0) {
                    m_state = S_BOOLEAN;
                    i += status - 1;
                    break;
                }
                m_state = S_ERROR;
                break; // S_COLON

            case S_BOOLEAN:
                if (isspace(c)) {
                    break;
                }
                if (c == ',') {
                    m_state = S_COMMA;
                    break;
                }
                if (isArrayEnd(c, &array_count)) {
                    m_state = S_ARRAY_END;
                    break;
                }
                if (isObjectEnd(c, &object_count)) {
                    m_state = S_OBJECT_END;
                    break;
                }
                m_state = S_ERROR;
                break; // S_BOOLEAN

            case S_ERROR: break;
            case S_END: break;
        }
        if (m_state == S_ERROR) {
            return false;
        }
        i++;
    }

    if (m_state != S_ERROR && array_count >= 0 && object_count >= 0)
        return true;
    return false;
}

KnownSourceType
detectKnownSource(const std::string &input)
{
    static bool err = false;
    static const SingleRegex known_source_sensor_data_re(
        "^\\{\\\"sensor_data\\\":\\\"",
        err,
        "known_source_sensor_data"
    );
    if (known_source_sensor_data_re.hasMatch(input)) {
        return SOURCE_TYPE_SENSOR_DATA;
    }
    return SOURCE_TYPE_UNKNOWN;
}

int
definePrefixedJson(const std::string &input)
{
    static const size_t MAX_JSON_PREFIX_LEN = 32;
    static const size_t MIN_PARAMETER_LEN = 4;
    if (input.size() < MIN_PARAMETER_LEN) {
        return -1;
    }

    for (size_t i = 0; i < std::min(input.size(), MAX_JSON_PREFIX_LEN) - 2 ; ++i) {
        if (input[i] == '-' && input[i+1] == '{') return i + 1;
    }

    return -1;
}

bool
isScreenedJson(const std::string &input)
{
    static bool err = false;
    static const SingleRegex screened_json_re(
        R"(^"{\s*\\"\w+\\"\s*:\s*\\"["\w])",
        err,
        "screened_json"
    );

    if (screened_json_re.hasMatch(input)) {
        return true;
    }
    return false;
}

} // namespace Util
} // namespace Waap
