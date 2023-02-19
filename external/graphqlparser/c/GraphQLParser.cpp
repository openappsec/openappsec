/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "GraphQLParser.h"
#include "../GraphQLParser.h"
#include "../AstNode.h"

#include <cstdlib>

struct GraphQLAstNode *graphql_parse_string(const char *text, const char **error) {
  return reinterpret_cast<struct GraphQLAstNode *>(facebook::graphql::parseString(text, error).release());
}

struct GraphQLAstNode *graphql_parse_string_with_experimental_schema_support(
    const char *text, const char **error) {
  return reinterpret_cast<struct GraphQLAstNode *>(facebook::graphql::parseStringWithExperimentalSchemaSupport(
                                                     text, error).release());
}

struct GraphQLAstNode *graphql_parse_file(FILE *file, const char **error) {
  return reinterpret_cast<struct GraphQLAstNode *>(facebook::graphql::parseFile(file, error).release());
}

struct GraphQLAstNode *graphql_parse_file_with_experimental_schema_support(
    FILE *file, const char **error) {
  return reinterpret_cast<struct GraphQLAstNode *>(facebook::graphql::parseFileWithExperimentalSchemaSupport(file, error).release());
}

void graphql_error_free(const char *error) {
  std::free((void *)(error)); // NOLINT
}
