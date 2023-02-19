/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
package main

/*
#cgo pkg-config: libgraphqlparser

#include "c/GraphQLAst.h"
#include "c/GraphQLAstNode.h"
#include "c/GraphQLAstVisitor.h"
#include "c/GraphQLParser.h"
#include <stdlib.h>

int printField_cgo(struct GraphQLAstField *field, void *unused);
*/
import "C"

import "errors"
import "fmt"
import "unsafe"

//export printField
func printField(field *C.struct_GraphQLAstField, unused unsafe.Pointer) int {
	fmt.Printf("field : %s\n", C.GoString(C.GraphQLAstName_get_value(C.GraphQLAstField_get_name(field))))
	return 0
}

func parse(query string) (*C.struct_GraphQLAstNode, error) {
	graphql := C.CString(query)
	cError := (*C.char)(nil)
	ast := C.graphql_parse_string(graphql, &cError)
	C.free(unsafe.Pointer(graphql))

	if ast == nil {
		err := errors.New(C.GoString(cError))
		C.graphql_error_free(cError)
		return nil, err
	}
	return ast, nil
}

func main() {
	ast, err := parse("query myquery { myfield }")
	if err != nil {
		fmt.Printf("BUG: unexpected parse error: %s", err)
		return
	}
	visitor_callbacks := C.struct_GraphQLAstVisitorCallbacks{visit_field: (C.visit_field_func)(C.printField_cgo)}
	C.graphql_node_visit(ast, &visitor_callbacks, nil)

	C.graphql_node_free(ast)

	ast2, err2 := parse("query errorQuery on oops { myfield }")
	if err2 != nil {
		fmt.Printf("Example error: %s\n", err2)
	}
	if ast2 != nil {
		fmt.Printf("BUG: we should have got a null AST back, but we got %s\n", ast2)
	}
}
