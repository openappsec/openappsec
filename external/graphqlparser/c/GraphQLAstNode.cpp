/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "GraphQLAstNode.h"
#include "../AstNode.h"

using facebook::graphql::ast::Node;

void graphql_node_get_location(const struct GraphQLAstNode *node,
                               struct GraphQLAstLocation *location) {
  const auto *realNode = reinterpret_cast<const Node *>(node);
  const auto &loc = realNode->getLocation();
  location->beginLine = loc.begin.line;
  location->beginColumn = loc.begin.column;
  location->endLine = loc.end.line;
  location->endColumn = loc.end.column;
}

void graphql_node_free(struct GraphQLAstNode *node) {
  delete reinterpret_cast<Node *>(node);
}
