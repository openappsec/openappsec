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

#include "ParserGql.h"
#include "graphqlparser/AstNode.h"
#include "graphqlparser/AstVisitor.h"
#include "graphqlparser/GraphQLParser.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_GQL);

const std::string ParserGql::m_parserName = "gqlParser";

ParserGql::ParserGql(IParserReceiver &receiver, size_t parser_depth) :
    m_receiver(receiver),
    m_error(false),
    m_curNameValues(0),
    m_parser_depth(parser_depth)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    dbgTrace(D_WAAP_PARSER_GQL) << "parser_depth=" << parser_depth;
}

ParserGql::~ParserGql() {
    dbgFlow(D_WAAP_PARSER_GQL);
}

size_t ParserGql::push(const char* buf, size_t len) {
    dbgTrace(D_WAAP_PARSER_GQL) << "buf='" << std::string(buf, len) << "'";
    if (len > 0) {
        dbgTrace(D_WAAP_PARSER_GQL) << "appending " << len << " bytes ...";
        m_buffer.append(buf, len);
        return len;
    }

    const char *errorstr = nullptr;
    dbgTrace(D_WAAP_PARSER_GQL) << "parsing ...";
    std::unique_ptr<facebook::graphql::ast::Node> ast = facebook::graphql::parseString(m_buffer.c_str(), &errorstr);
    if (!ast) {
        dbgTrace(D_WAAP_PARSER_GQL) << "GraphQL parser failed: " << errorstr;
        m_error = true;
        return 0;
    }

    // Walk over AST and call the visitXXX callbacks
    ast->accept(this);

    // Handle corner case of last name visited without value: don't forget to output that name too
    if (m_curNameValues == 0 && !m_curNodeName.empty()) {
        dbgTrace(D_WAAP_PARSER_GQL) << "handle last name: '" << m_curNodeName << "'";
        if (m_receiver.onKv(
                m_curNodeName.data(), m_curNodeName.size(), "", 0, BUFFERED_RECEIVER_F_BOTH, m_parser_depth
            ) != 0) {
            m_error = true;
        }
    }

    return len;
}

void ParserGql::finish() {
    push(NULL, 0);
}

const std::string &
ParserGql::name() const {
    return m_parserName;
}

bool ParserGql::error() const {
    return m_error;
}

bool ParserGql::visitValue(const char *value)
{
    dbgTrace(D_WAAP_PARSER_GQL) << "'" << value << "'";
    m_curNameValues++;
    return m_receiver.onKv(
        m_curNodeName.data(), m_curNodeName.size(), value, strlen(value), BUFFERED_RECEIVER_F_BOTH, m_parser_depth
    );
}

bool ParserGql::visitName(const facebook::graphql::ast::Name &node)
{
    dbgTrace(D_WAAP_PARSER_GQL) << node.getValue() << "'";
    bool ret = true;
    if (m_curNameValues == 0 && !m_curNodeName.empty()) {
        ret = m_receiver.onKv(
            m_curNodeName.data(), m_curNodeName.size(), "", 0, BUFFERED_RECEIVER_F_BOTH, m_parser_depth
        );
    }
    // wait for next name
    m_curNodeName = std::string(node.getValue());
    m_curNameValues = 0;
    return ret;
}

bool ParserGql::visitIntValue(const facebook::graphql::ast::IntValue &node)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    return visitValue(node.getValue());
}

bool ParserGql::visitFloatValue(const facebook::graphql::ast::FloatValue &node)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    return visitValue(node.getValue());
}

bool ParserGql::visitStringValue(const facebook::graphql::ast::StringValue &node)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    return visitValue(node.getValue());
}

bool ParserGql::visitBooleanValue(const facebook::graphql::ast::BooleanValue &node)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    return visitValue(node.getValue() ? "true" : "false");
}

bool ParserGql::visitNullValue(const facebook::graphql::ast::NullValue &node)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    return visitValue("null");
}

bool ParserGql::visitEnumValue(const facebook::graphql::ast::EnumValue &node)
{
    dbgFlow(D_WAAP_PARSER_GQL);
    return visitValue(node.getValue());
}
