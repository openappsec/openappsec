# Copyright 2019-present, GraphQL Foundation
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from casing import snake

from license import C_LICENSE_COMMENT

def struct_name(type):
  return 'GraphQLAst' + type


def return_type(type):
  if type == 'OperationKind' or type == 'string':
    return 'const char *'

  if type == 'boolean':
    return 'int'

  return 'const struct %s *' % struct_name(type)


def field_prototype(owning_type, type, name, nullable, plural):
  st_name = struct_name(owning_type)
  if plural:
    return 'int %s_get_%s_size(const struct %s *node)' % (
      st_name, snake(name), st_name)
  else:
    ret_type = return_type(type)
    return '%s %s_get_%s(const struct %s *node)' % (
      ret_type, st_name, snake(name), st_name)


class Printer(object):
  '''Printer for the pure C interface to the AST.

  Merely a set of wrappers around the C++ interface; makes it possible
  to use the AST from C code and simplifies the task of writing
  bindings for other langugages.

  The mapping is as follows:

  - For each concrete type, you get an opaque C struct type,
  accessible only by pointer.

  - For each singular field of a concrete type, you get an accessor
  function, returning said field in the obvious way.

  - For each plural field of a concrete type, you get an accessor
  function telling you its size. For access to elements of a plural
  field, you can use the visitor API.

  - For each union type, you get nothing specific (REVIEW), but you
    can use the visitor API to work around this entirely.

  '''

  def __init__(self):
    self._current_type = None

  def start_file(self):
    print C_LICENSE_COMMENT + '''/** @generated */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

'''

  def end_file(self):
    print '''

#ifdef __cplusplus
}
#endif
'''

  def start_type(self, name):
    # Forward declarations for AST nodes.
    st_name = struct_name(name)
    print 'struct ' + st_name + ';'
    self._current_type = name

  def field(self, type, name, nullable, plural):
    print field_prototype(self._current_type, type, name, nullable, plural) + ';'

  def end_type(self, name):
    print

  def start_union(self, name):
    print 'struct ' + struct_name(name) + ';'

  def union_option(self, option):
    pass

  def end_union(self, name):
    print
