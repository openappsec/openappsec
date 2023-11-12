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

#ifndef __PARSER_GQL_H
#define __PARSER_GQL_H

#include <string.h>
#include <vector>

#include "ParserBase.h"
#include "graphqlparser/Ast.h"
#include "graphqlparser/AstNode.h"
#include "graphqlparser/AstVisitor.h"
#include "KeyStack.h"

class ParserGql : public ParserBase, public facebook::graphql::ast::visitor::AstVisitor {
public:
    ParserGql(IParserReceiver &receiver, size_t parser_depth);
    virtual ~ParserGql();
    size_t push(const char *data, size_t data_len);
    void finish();
    virtual const std::string &name() const;
    bool error() const;
    virtual size_t depth() { return 0; }
private:
    IParserReceiver &m_receiver;
    bool m_error;
    std::string m_buffer;
    std::string m_curNodeName;
    int m_curNameValues;

    bool visitValue(const char *value);

    // Callbacks from the parser
    bool visitName(const facebook::graphql::ast::Name &node) override;
    bool visitIntValue(const facebook::graphql::ast::IntValue &node) override;
    bool visitFloatValue(const facebook::graphql::ast::FloatValue &node) override;
    bool visitStringValue(const facebook::graphql::ast::StringValue &node) override;
    bool visitBooleanValue(const facebook::graphql::ast::BooleanValue &node) override;
    bool visitNullValue(const facebook::graphql::ast::NullValue &node) override;
    bool visitEnumValue(const facebook::graphql::ast::EnumValue &node) override;
public:
    static const std::string m_parserName;
    size_t m_parser_depth;
};

#endif // __PARSER_JQL_H
