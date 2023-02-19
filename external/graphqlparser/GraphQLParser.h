/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * The purpose of this file is to provide a nice interface to parsing
 * GraphQL, rather than the old-fashioned interface provided by bison
 * and flex.
 */

#pragma once

#include <memory>
#include <stdio.h>

namespace facebook {
namespace graphql {

namespace ast {
  class Node;
}

/**
 * Parse the given GraphQL source string, returning an AST. Returns
 * nullptr on error and, if error is not null, places a string
 * describing what went wrong in error that must be freed with free(3).
 */
std::unique_ptr<ast::Node> parseString(const char *text, const char **error);

/**
 * Like parseString, but enables support for the experimental type
 * definition syntax from https://github.com/facebook/graphql/pull/90 .
 */
std::unique_ptr<ast::Node> parseStringWithExperimentalSchemaSupport(
  const char *text, const char **error);

/**
 * Read and parse GraphQL source from the given file, returning an
 * AST. Returns nullptr on error and, if error is not null, places an
 * error string in error that must be freed with free(3).
 */
std::unique_ptr<ast::Node> parseFile(FILE *file, const char **error);

/**
 * Like parseFile, but enables support for the experimental type
 * definition syntax from https://github.com/facebook/graphql/pull/90 .
 */
std::unique_ptr<ast::Node> parseFileWithExperimentalSchemaSupport(
  FILE *file, const char **error);

}
}
