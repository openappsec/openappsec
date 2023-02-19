#!/usr/bin/env python
# Copyright 2019-present, GraphQL Foundation
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from ctypes import *
from GraphQLParser import *

def print_field(field, unused):
  field_name = GraphQLAstField_get_name(field)
  field_name_value = GraphQLAstName_get_value(field_name)
  print 'field : ' + field_name_value
  return 0

def main():
  error = POINTER(c_char)()
  ast = graphql_parse_string('query myquery { myfield }', byref(error))
  field_visitor_callbacks = GraphQLAstVisitorCallbacks(visit_field = visit_field_func(print_field))
  graphql_node_visit(ast, pointer(field_visitor_callbacks), None)

  graphql_node_free(ast)

  ast = graphql_parse_string('query errorQuery on oops { myfield }', byref(error))
  print 'Example error:', string_at(error)
  graphql_error_free(error)
  if ast:
    print 'BUG: we should have got a null AST back, but we got:', ast

if __name__ == '__main__':
  main()
