/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
package main

/*
struct GraphQLAstField;

int printField(struct GraphQLAstField *field, void *unused);

int printField_cgo(struct GraphQLAstField *field, void *unused) {
  return printField(field, unused);
}
*/
import "C"
