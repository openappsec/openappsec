# Copyright 2019-present, GraphQL Foundation
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from c import field_prototype, return_type, struct_name
from casing import title
from license import C_LICENSE_COMMENT

class Printer(object):
  '''Printer for the implementation of the pure C interface to the AST.
  '''

  def __init__(self):
    self._current_type = None

  def start_file(self):
    print(C_LICENSE_COMMENT + '''/** @generated */

#include "GraphQLAst.h"
#include "../Ast.h"

using namespace facebook::graphql::ast;  // NOLINT
''')

  def end_file(self):
    pass

  def start_type(self, name):
    self._current_type = name

  def field(self, type, name, nullable, plural):
    print(field_prototype(self._current_type, type, name, nullable, plural) + ' {')
    print('  const auto *realNode = reinterpret_cast<const %s *>(node);' % self._current_type)
    title_name = title(name)
    call_get = 'realNode->get%s()' % title_name
    if plural:
      if nullable:
        print('  return %s ? %s->size() : 0;' % (call_get, call_get))
      else:
        print('  return %s.size();' % call_get)
    else:
      if type in ['string', 'OperationKind', 'boolean']:
        print('  return %s;' % call_get)
      else:
        fmt = '  return reinterpret_cast<const struct %s *>(%s%s);'
        print(fmt % (struct_name(type), '' if nullable else '&', call_get))

    print('}')

  def end_type(self, name):
    pass

  def start_union(self, name):
    pass

  def union_option(self, option):
    pass

  def end_union(self, name):
    pass
