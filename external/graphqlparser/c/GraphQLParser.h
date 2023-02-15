/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This file provides C wrappers for ../GraphQLParser.h.
 */

struct GraphQLAstNode;

/**
 * Parse the given GraphQL source string, returning an AST. Returns
 * NULL on error. Return value must be freed with
 * graphql_node_free(). If NULL is returned and error is not NULL, an
 * error message is placed in error and must be freed with
 * graphql_error_free().
 */
struct GraphQLAstNode *graphql_parse_string(
    const char *text, const char **error);

struct GraphQLAstNode *graphql_parse_string_with_experimental_schema_support(
    const char *text, const char **error);

/**
 * Read and parse GraphQL source from the given file, returning an
 * AST. Returns nullptr on error. Return value must be freed with
 * graphql_node_free(). If NULL is returned and error is not NULL, an
 * error message is placed in error and must be freed with
 * graphql_error_free().
 */
struct GraphQLAstNode *graphql_parse_file(FILE *file, const char **error);

struct GraphQLAstNode *graphql_parse_file_with_experimental_schema_support(
    FILE *file, const char **error);

/**
 * Frees an error.
 */
void graphql_error_free(const char *error);

#ifdef __cplusplus
}
#endif
