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

#include "PHPSerializedDataParser.h"
#include "log_generator.h"
#include <errno.h>

USE_DEBUG_FLAG(D_WAAP_PARSER_PHPSERIALIZE);

const std::string PHPSerializedDataParser::m_parserName = "PHPSerializedDataParser";

PHPSerializedDataParser::PHPSerializedDataParser(IParserStreamReceiver &outReceiver, size_t parser_depth) :
    m_state(),
    m_outReceiver(outReceiver),
    m_keyStack("php_serialized"),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE)
        << "parser_depth="
        << parser_depth;
}

size_t
PHPSerializedDataParser::push(const char* buf, size_t len)
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push()";
    size_t i = 0;
    char c;

    if (len == 0)
    {
        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): len = 0 ";
        if(m_state.phase_state != s_start) {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): len = 0 ;"
                "phase_state != s_start ; m_state.phase_state: " <<  m_state.phase_state;
            m_error = true;
            return -1;
        }
        switch (m_state.kv_state)
        {
            case (s_onKey):
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): len = 0 ; s_onKey";
                m_outReceiver.onKey(m_value.c_str(), m_value.length());
                break;
            }
            case (s_onValue):
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): len = 0 ; s_onValue";
                m_outReceiver.onValue(m_value.c_str(), m_value.length());
                m_outReceiver.onKvDone();
                break;
            }
            case (s_clear_kv):
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): len = 0 ; s_clear_kv;"
                    "State Finished has expected";
                // State Finished has expected.
                break;
            }
        }
        return 1;
    }

    while (i < len)
    {
        c = buf[i];
        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push():while(i<len)" "check: " << c
            << " state: " << m_state.phase_state;
        switch (m_state.phase_state)
        {
            case s_data_end:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_data_end";
                if (!onDataEnd(c, true))
                {
                    // Error
                    return -1;
                }
                break;
            }
            case s_class_data_end:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_class_data_end";
                if (!onDataEnd(c, false))
                {
                    // Error
                    return -1;
                }
                break;
            }
            case s_value:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_value";
                size_t result = handleValue(c);
                if ( result == (size_t)-1 )
                {
                    return -1;
                }
                break;
            }
            // Getting length of complex types like: array, string, object and custom.
            case s_length:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_length";
                if (c == ':')
                {
                    // convert length string to int.
                    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): m_length" <<
                        m_length;
                    char *pEnd = NULL;
                    m_state.length = ::strtoll(m_length.c_str(), &pEnd, 10);
                    if (pEnd != m_length.c_str() + m_length.length())
                    {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) <<
                            "Failed to convert length from string to integer (Invalid arguments).";
                        m_error = true;
                        return -1;
                    }
                    m_state.phase_state = s_value;
                    m_length.clear();
                    break;
                }
                m_length.push_back(c);
                break;
            }
            // primitive colon belongs to int, double, bool, ref which does not require length case
            case s_prim_colon:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_prim_colon";
                if (c != ':')
                {
                    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_prim_colon" <<
                        "Error: ':' should appear, instead " << c << " appeared";
                    m_error = true;
                    return -1;
                }
                m_state.phase_state = s_value;
                break;
            }
            // belongs to object, string, array, class which require length case
            case s_colon:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_colon";
                if (c != ':')
                {
                    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_colon" <<
                        "Error: ':' should appear, instead " << c << " appeared";
                    m_error = true;
                    return -1;
                }
                m_state.phase_state = s_length;
                break;
            }
            // s_start is being called every time we need to discover new object type
            // (state is first intilaized by s_start).
            case s_start:
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start";
                switch (tolower(c)) {
                    case 'n':
                    {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: NULL";
                        m_state.type_state = s_null;
                        m_state.phase_state = s_value;
                        break;
                    }
                    case 'a':
                    {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Array";
                        //  Array cannot be key. Throw failure.
                        if (m_state.kv_state == s_onKey)
                        {
                            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: " <<
                                "Array cannot be a key";
                            m_error = true;
                            return -1;
                        }
                        // If stack not empty and Value is array then value should be empty.
                        //      next key will be the key inside the array.
                        if (!m_stack.empty())
                        {
                            // Send empty value for the case of array/object as a subitem
                            m_value = "";
                            onStateValue();
                            m_state.kv_state = s_clear_kv;
                        }
                        m_state.type_state = s_start_array;
                        m_state.phase_state = s_colon;
                        break;
                    }
                    case 's': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: String";
                        m_state.type_state = s_start_string;
                        m_state.phase_state = s_colon;
                        break;
                    }
                    case 'b': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Boolean";
                        if (m_state.kv_state == s_onKey)
                        {
                            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: " <<
                                "Boolean cannot be a key";
                            m_error = true;
                            return -1;
                        }
                        m_state.type_state = s_boolean_OnValue;
                        m_state.phase_state = s_prim_colon;
                        break;
                    }
                    case 'i': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Integer";
                        m_state.type_state = s_integer_onValue;
                        m_state.phase_state = s_prim_colon;
                        break;
                    }
                    // parsing double as integer is ok in this case because integer are not really validated,
                    //  instead they are reported as strings.
                    case 'd': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Double";
                        m_state.type_state = s_integer_onValue;
                        m_state.phase_state = s_prim_colon;
                        break;
                    }
                    case 'o': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Object";
                        if (m_state.kv_state == s_onKey)
                        {
                            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: " <<
                                "Object cannot be a key";
                            m_error = true;
                            return -1;
                        }
                        if (!m_stack.empty())
                        {
                            m_value = "";
                            onStateValue();
                            m_state.kv_state = s_clear_kv;
                        }
                        m_state.isObject = true;
                        m_state.type_state = s_start_string;
                        m_state.phase_state = s_colon;
                        break;
                    }
                    case 'c': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Class";
                        if (m_state.kv_state == s_onKey)
                        {
                            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: " <<
                                "Class cannot be a key";
                            m_error = true;
                            return -1;
                        }
                        if (!m_stack.empty())
                        {
                            m_value = "";
                            onStateValue();
                            m_state.kv_state = s_clear_kv;
                        }
                        m_state.isClass = true;
                        m_state.type_state = s_start_string;
                        m_state.phase_state = s_colon;
                        break;
                    }
                    case 'r': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: Reference";
                        m_state.type_state = s_ref_onValue;
                        m_state.phase_state = s_prim_colon;
                        break;
                    }
                    case '}': {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start: }";
                        if (!onDataEnd(c, false))
                        {
                            // Error
                            return -1;
                        }
                        break;
                    }
                    default: {
                        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) <<
                            "PHPSerializedDataParser::push(): s_start: Unexpected Error. "
                            "Invalid char in s_start: " << c;
                        m_error = true;
                        return -1;
                    }
                }
            }
        }
        ++i;
    }
    return 0;
}


size_t PHPSerializedDataParser::handleValue (const char &c)
{
    switch (m_state.type_state)
    {
        case s_start_class:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_class";
            if (c != '{')
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_class " <<
                    "Class start with: " << c << " instead of {";
                m_error = true;
                return -1;
            }
            std::string keyStack("Class");
            std::string val("");
            m_keyStack.push(keyStack.c_str(), keyStack.length());
            m_key = m_value;
            m_outReceiver.onKey(m_value.c_str(), m_value.length());
            m_outReceiver.onValue(val.c_str(), val.length());
            m_outReceiver.onKvDone();
            m_value.clear();
            // changing isClass to false because this object handle class definition.
            m_state.isClass = false;
            m_state.current_length = m_state.length;
            m_state.kv_state = s_onKey;
            m_state.type_state = s_class_onValue;
            State state = m_state;
            m_stack.push(state);
            break;
        }
        case s_class_onValue:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_class_onValue";
            // counting down the characters that we get on buffer.
            // if we get all chars '}' should occur.
            if (m_state.current_length != 0)
            {
                m_state.current_length--;
                m_value.push_back(c);
                break;
            }
            // Class object can handle string or more serialized data.
            // If it's a string than the parser will retuen with error
            // else will parse it normaly.
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): End of Class object" <<
                " sending class object data to PHPSerializedDataParser";
            PHPSerializedDataParser psdp(m_outReceiver, m_parser_depth);
            psdp.push(m_value.c_str(), m_value.length());
            if(psdp.error())
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): " <<
                    "class object data return with an error !";
                m_outReceiver.onKey(m_key.c_str(), m_key.length());
                m_outReceiver.onValue(m_value.c_str(), m_value.length());
                m_outReceiver.onKvDone();
                m_value.clear();
                m_key.clear();
            }
            m_state.phase_state = s_class_data_end;
            break;
        }
        case s_start_object:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_object";
            if (c != '{')
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_object" <<
                    "Object start with: " << c << " instead of {";
                m_error = true;
                return -1;
            }
            std::string keyStack("Object");
            std::string val("");
            m_keyStack.push(keyStack.c_str(), keyStack.length());
            m_outReceiver.onKey(m_value.c_str(), m_value.length());
            m_outReceiver.onValue(val.c_str(), val.length());
            m_outReceiver.onKvDone();
            m_value.clear();
            // changing isObject to false because this object handle class definition.
            m_state.isObject = false;
            m_state.kv_state = s_onKey;
            m_state.phase_state = s_start;
            State state = m_state;
            m_stack.push(state);
            break;
        }
        case s_start_array:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_array";
            if (c != '{')
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_array" <<
                    "Array start with: " << c << " instead of {";
                m_error = true;
                return -1;
            }
            std::string keyVal("array");
            m_keyStack.push(keyVal.c_str(), keyVal.length());
            m_state.kv_state = s_onKey;
            m_state.phase_state = s_start;
            State state = m_state;
            m_stack.push(state);
            break;
        }
        case s_start_string:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_string";
            if (c != '"')
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_start_string" <<
                    "string start with: " << c << " instead of \"";
                m_error = true;
                return -1;
            }
            m_state.current_length = 0;
            m_state.type_state = s_string_onValue;
            break;
        }
        case s_string_onValue:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_onValue";
            if (c != '"')
            {
                if (c == '\\')
                {
                    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_onValue " <<
                        "escape ?:   " << c;
                    m_state.current_length++;
                    m_state.type_state = s_string_escape;
                    break;
                }
                m_value.push_back(c);
                m_state.current_length++;
                break;
            }
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_onValue" <<
                " End of String";
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_onValue" <<
                "m_state.isClass: " << m_state.isClass;
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_onValue" <<
                " m_state.isObject: " << m_state.isObject;
            if (m_state.isObject || m_state.isClass)
            {
                m_state.type_state = s_object_string_calc;
            }
            else
            {
                m_state.type_state = s_string_calc;
            }
            break;
        }
        case s_string_escape:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_escape";
            if (c == 'x')
            {
                m_state.type_state = s_string_escape_x_1;
            }
            else if (c == '0')
            {
                m_value.push_back('@');
                m_state.type_state = s_string_onValue;
            }
            else
            {
                m_value.push_back('\\');
                m_value.push_back(c);
                m_state.current_length++;
                m_state.type_state = s_string_onValue;
            }
            break;
        }
        case s_string_escape_x_1:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_escape_x_1";
            if (c == '0')
            {
                m_state.type_state = s_string_escape_x_2;
                break;
            }
            m_value = m_value + "\\x";
            m_value.push_back(c);
            m_state.current_length = m_state.current_length + 2;
            m_state.type_state = s_string_onValue;
            break;
        }
        case s_string_escape_x_2:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_escape_x_2";
            if (c == '0')
            {
                m_value.push_back('@');
                m_state.type_state = s_string_onValue;
                break;
            }
            m_value = m_value + "\\x0";
            m_value.push_back(c);
            m_state.current_length = m_state.current_length + 3;
            m_state.type_state = s_string_onValue;
            break;
        }
        case s_object_string_calc:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_object_string_calc";
            if (c != ':') {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_object_string_calc" <<
                " Error: After object name ':' should appear instead " << c << " appeared";
                m_error = true;
                return -1;
            }
            // check string length
            if (m_state.current_length != m_state.length)
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_object_string_calc" <<
                    " m_state.current_length: " << m_state.current_length << "!=" << " m_state.length: "
                    << m_state.length;
                m_error = true;
                return -1;
            }
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_object_string_calc" <<
                " Start object";
            m_state.current_length = 0;
            m_state.phase_state = s_length;
            if (m_state.isObject)
            {
                m_state.type_state = s_start_object;
            }
            else
            {
                m_state.type_state = s_start_class;
            }
            break;
        }
        case s_string_calc:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_calc";
            if (c != ';') {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_calc" <<
                " Error: string should end with ';' not with " << c;
                m_error = true;
                return -1;
            }
            // check string length
            if (m_state.current_length != m_state.length)
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_string_calc" <<
                    " m_state.current_length: " << m_state.current_length << "!=" << " m_state.length: "
                        << m_state.length;
                m_error = true;
                return -1;
            }
            if (handleStateAfterFinish("String"))
            {
                break;
            }
            m_state.current_length = 0;
            m_value.clear();
            m_state.phase_state = s_start;
            break;
        }
        case s_integer_onValue:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_integer_onValue";
            if ( c != ';')
            {
                m_value.push_back(c);
                break;
            }
            if (handleStateAfterFinish("Integer"))
            {
                break;
            }
            m_value.clear();
            m_state.phase_state = s_start;
            break;
        }
        case s_ref_onValue:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_ref_onValue";
            if ( c != ';')
            {
                m_value.push_back(c);
                break;
            }
            if (handleStateAfterFinish("Reference"))
            {
                break;
            }
            m_value.clear();
            m_state.phase_state = s_start;
            break;
        }
        case s_boolean_OnValue:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_boolean_OnValue";
            if (m_value.length() > 1)
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_boolean_OnValue" <<
                    " Error length is bigger than 1 : Boolean should be with 0 or 1";
                m_error = true;
                return -1;
            }
            if ( c != ';' )
            {
                m_value.push_back(c);
                break;
            }
            // boolean can be 0 or 1 only.
            if (m_value.compare("1") != 0 && m_value.compare("0") != 0)
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_boolean_OnValue" <<
                    " Error Boolean value is not 0 or 1 : " << m_value;
                m_error = true;
                return -1;
            }
            if (handleStateAfterFinish("Boolean"))
            {
                break;
            }
            m_value.clear();
            m_state.phase_state = s_start;
            break;
        }
        case s_null:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_null";
            if (c != ';')
            {
                dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): s_null" <<
                    " Null should end with ';' not with : " << c;
                m_error = true;
                return -1;
            }
            if (handleStateAfterFinish("Null"))
            {
                break;
            }
            m_value.clear();
            m_state.phase_state = s_start;
            break;
        }
        default:
        {
            dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push(): default" <<
                " Unexpected Error.";
            m_error = true;
            return -1;
        }
    }
    return 0;
}

//  Handle data end of an object and if he got the right number of values.
//  termChar = is char terminator (f.e })
//  checkEndBlock enable check if last char is equal to }
bool
PHPSerializedDataParser::onDataEnd(char termChar, bool checkEndBlock)
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::onDataEnd (phase_state=" <<
        m_state.phase_state << ", termChar='" << termChar << "')";
    if (m_state.current_length != m_state.length)
    {
        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push():" <<
            "current_length " << m_state.current_length << "!=" << " m_state.length " << m_state.length;
        m_error = true;
        return false;
    }

    if (termChar != '}'  && checkEndBlock)
    {
        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::push():" <<
            "termChar is not }";
        m_error = true;
        return false;
    }

    if (m_stack.empty())
    {
        return true;
    }

    m_state.isObject = false;
    m_keyStack.pop(m_keyStack.first().c_str());
    m_state = m_stack.top();
    m_stack.pop();
    m_state.phase_state = s_start;

    return true;
}

void
PHPSerializedDataParser::onEmptyStack(std::string type)
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::onEmptyStack(): stack is empty.";
    m_outReceiver.onKey(type.c_str(), type.length());
    m_outReceiver.onValue(m_value.c_str(), m_value.length());
    m_outReceiver.onKvDone();
    m_value.clear();
    m_state.current_length = 0;
    m_state.phase_state = s_start;
}

void
PHPSerializedDataParser::onStateKey()
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::onStateKey()";
    if (m_keyStack.size() >= 1)
    {
        m_value =  m_keyStack.str() + "." + m_value;
    }
    m_outReceiver.onKey(m_value.c_str(), m_value.length());
    // clear current length
    m_state.current_length = 0;
    //clear value
    m_value.clear();
    // change state from key to value.
    m_state.kv_state = s_onValue;
    m_state.phase_state = s_start;
}

void
PHPSerializedDataParser::onStateValue()
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::onStateValue()";
    // change state from value to key.
    m_state.kv_state = s_onKey;
    // Look at our last state and raise its member counter.
    State &stack_state = m_stack.top();
    stack_state.current_length++;
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "stack_state.current_length: " << stack_state.current_length;
    // set Value and KvDone.
    m_outReceiver.onValue(m_value.c_str(), m_value.length());
    m_outReceiver.onKvDone();
}

// checking if current length is equal to the length the object got
//  and move it to s_data_end
bool
PHPSerializedDataParser::onCheckLength()
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::onCheckLength()";
    State &stack_state = m_stack.top();
    if (stack_state.current_length == stack_state.length)
    {
        m_state.current_length = 0;
        m_value.clear();
        m_state = m_stack.top();
        m_state.phase_state = s_data_end;
        m_state.kv_state = s_clear_kv;
        return true;
    }
    return false;
}

// Handle State after finishing reading data from a type.
bool
PHPSerializedDataParser::handleStateAfterFinish(const std::string &type)
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::handleStateAfterFinish()";
    // If stack empty that means we don't have last state : Object || Custom || Array
    if (m_stack.empty())
    {
        onEmptyStack(type);
        return true;
    }
    if (m_state.kv_state == s_onKey)
    {
        onStateKey();
        return true;
    }
    // If stack is not empty check last state Object || Custom || Array
    // change state from value - if state on key should throw error on s_start
    // key must be value on boolean
    onStateValue();
    if (onCheckLength())
    {
        return true;
    }
    return false;
}

void
PHPSerializedDataParser::finish()
{
    dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::finish()";
    push(NULL, 0);
}

const std::string &
PHPSerializedDataParser::name() const
{
    return m_parserName;
}

bool
PHPSerializedDataParser::error() const
{
    if (m_error)
    {
        dbgTrace(D_WAAP_PARSER_PHPSERIALIZE) << "PHPSerializedDataParser::error(): parser returned with an error";
        return true;
    }
    return false;
}
