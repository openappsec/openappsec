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

struct GraphQLAstNode;

/**
 * Serialize the given AST to JSON. The returned C string must be
 * freed with free().
 */
const char *graphql_ast_to_json(const struct GraphQLAstNode *node);

#ifdef __cplusplus
}
#endif
