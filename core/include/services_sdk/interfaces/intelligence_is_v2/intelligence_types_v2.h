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

#ifndef __INTELLIGENCE_TYPES_V2_H__
#define __INTELLIGENCE_TYPES_V2_H__

#include <string>
#include <chrono>
#include <unordered_map>
#include "debug.h"

namespace Intelligence_IS_V2
{

enum class AttributeKeyType {
    MAIN,
    REGULAR,
    NONE
};

enum class Operator
{
    AND,
    OR,
    NONE
};

enum class Condition
{
    EQUALS,
    NOT_EQUALS,
    MATCH,
    STARTS_WITH,
    CONTAINS,
    IN,
    NOT_IN,
    GREATER_THAN,
    LESS_THAN
};

enum class CursorState {
    START,
    IN_PROGRESS,
    DONE
};

enum class ResponseStatus
{
    DONE,
    IN_PROGRESS
};

enum class ObjectType { ASSET, ZONE, CONFIGURATION, COUNT };

const std::string & convertConditionTypeToString(const Condition &condition_type);
const std::string & convertOperationTypeToString(const Operator &operation_type);
std::string createAttributeString(const std::string &key, AttributeKeyType type);
ResponseStatus convertStringToResponseStatus(const std::string &status);

class IntelligenceException : public std::exception
{
public:
    IntelligenceException() : message() {}
    IntelligenceException(const std::string &msg) : message(msg) {}

    const char * what() const throw() { return message.c_str(); }

private:
    std::string message;
};

} // namespace Intelligence_IS_V2

#endif // __INTELLIGENCE_TYPES_V2_H__
