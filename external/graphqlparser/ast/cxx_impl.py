# Copyright 2019-present, GraphQL Foundation
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from license import C_LICENSE_COMMENT

class Printer(object):
  def __init__(self):
    pass

  def start_file(self):
    print(C_LICENSE_COMMENT + '''/** @generated */

#include "Ast.h"
#include "AstVisitor.h"

namespace facebook {
namespace graphql {
namespace ast {
''')

  def end_file(self):
    print('}  // namespace ast')
    print('}  // namespace graphql')
    print('}  // namespace facebook')

  def start_type(self, name):
    print('''void %s::accept(visitor::AstVisitor *visitor) const {
  if (visitor->visit%s(*this)) {
''' % (name, name))

  def field(self, type, name, nullable, plural):
    if type in ['OperationKind', 'string', 'boolean']:
      return

    if plural:
      accept = '{ for (const auto &x : *%s_) { x->accept(visitor); } }' % name
      if nullable:
        accept = 'if (%s_) %s' % (name, accept)
      print('    ' + accept)
    else:
      accept = '%s_->accept(visitor);' % name
      if nullable:
        accept = 'if (%s_) { %s }' % (name, accept)
      print('    ' + accept)

  def end_type(self, name):
    print('''  }
  visitor->endVisit%s(*this);
}
''' % name)

  def start_union(self, name):
    pass

  def union_option(self, option):
    pass

  def end_union(self, name):
    pass
