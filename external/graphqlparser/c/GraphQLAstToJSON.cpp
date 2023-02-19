/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "GraphQLAstToJSON.h"

#include <cstring>

#include "../JsonVisitor.h"
#include "../AstNode.h"


const char *graphql_ast_to_json(const struct GraphQLAstNode *node)
{
  facebook::graphql::ast::visitor::JsonVisitor visitor;
  reinterpret_cast<const facebook::graphql::ast::Node *>(node)->accept(&visitor);
  return strdup(visitor.getResult().c_str());
}
