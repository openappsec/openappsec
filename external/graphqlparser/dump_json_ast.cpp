/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "AstNode.h"
#include "GraphQLParser.h"
#include "c/GraphQLAstToJSON.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>


using std::cout;
using std::cerr;
using std::endl;
using std::fopen;
using std::fclose;
using std::free;


int main(int argc, char **argv) {
  const char *error;
  FILE * in;
  if (argc > 1) {
    in = fopen(argv[1], "r"); // NOLINT
  } else {
    in = stdin;
  }
  auto AST = facebook::graphql::parseFile(in, &error);
  if (argc > 1) {
    fclose(in);
  }
  if (!AST) {
    cerr << "Parser failed with error: " << error << endl;
    free((void *)error);  // NOLINT
    return 1;
  }

  const char *json = graphql_ast_to_json(reinterpret_cast<const struct GraphQLAstNode *>(AST.get()));
  puts(json);
  free((void *)json);  // NOLINT

  return 0;
}
