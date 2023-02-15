/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "c/GraphQLAst.h"
#include "c/GraphQLAstForEachConcreteType.h"

#ifdef __cplusplus
extern "C" {
#endif
  
#define TYPEDEFS(type, snake_type)                                      \
  typedef int (*visit_##snake_type##_func)(const struct GraphQLAst##type *snake_type, void *user_data); \
  typedef void (*end_visit_##snake_type##_func)(const struct GraphQLAst##type *snake_type, void *user_data);

FOR_EACH_CONCRETE_TYPE(TYPEDEFS)

#define FUNC_MEMBER(type, snake_type)           \
  visit_##snake_type##_func visit_##snake_type; \
  end_visit_##snake_type##_func end_visit_##snake_type;
/**
 * Functions to be called when particular AST nodes are encountered.
 * visit_* functions are called in pre-order, and may return non-zero to
 * continue recursing into children (if any), or zero to skip them. end_visit_*
 * functions are called in post-order. Any particular function may be set to
 * NULL to indicate that the caller is not interested in the corresponding type
 * of AST node. (NULL visit_* functions act as though they simply returned
 * non-zero.)
 */
struct GraphQLAstVisitorCallbacks {
  FOR_EACH_CONCRETE_TYPE(FUNC_MEMBER)
};

struct GraphQLAstNode;

/**
 * Walk the AST rooted at the given node, issuing callbacks from the given
 * callbacks struct as appropriate. userData will be passed as the userData
 * argument to each callback.
 */
void graphql_node_visit(const struct GraphQLAstNode *node,
                        const struct GraphQLAstVisitorCallbacks *callbacks,
                        void *userData);

#ifdef __cplusplus
}
#endif

