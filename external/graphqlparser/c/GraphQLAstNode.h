/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque type representing a generic AST node. */
struct GraphQLAstNode;

/* A location in the AST. */
struct GraphQLAstLocation {
  unsigned int beginLine;
  unsigned int beginColumn;
  unsigned int endLine;
  unsigned int endColumn;
};

/* Fills location with location information for the given node. */
void graphql_node_get_location(const struct GraphQLAstNode *node,
                               struct GraphQLAstLocation *location);

void graphql_node_free(struct GraphQLAstNode *node);

#ifdef __cplusplus
}
#endif
