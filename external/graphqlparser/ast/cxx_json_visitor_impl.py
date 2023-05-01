# Copyright 2019-present, GraphQL Foundation
# All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from casing import title
from license import C_LICENSE_COMMENT

class Printer(object):
  def __init__(self):
    self._fields = []

  def start_file(self):
    print(C_LICENSE_COMMENT + '/** @generated */')

  def end_file(self):
    pass

  def start_type(self, name):
    self._fields = []

  def field(self, type, name, nullable, plural):
    if type == 'OperationKind':
      type = 'string'
    self._fields.append((type, name, nullable, plural))

  def end_type(self, name):
    titleName = title(name)
    anyFieldIsANode = any(type not in ('string, boolean')
                          for (type, _, _ ,_) in self._fields)
    if anyFieldIsANode:
      print('''bool JsonVisitor::visit%s(const %s &node) {
  visitNode();
  return true;
}
''' % (titleName, titleName))
    print('''void JsonVisitor::endVisit%(tn)s(const %(tn)s &node) {
  NodeFieldPrinter fields(*this, "%(tn)s", node);''' % {'tn': titleName})

    for (type, fieldName, nullable, plural) in self._fields:
      funcName = None
      if type == 'string':
        assert not plural, 'plural string fields not supported yet'
        funcName = 'printSingularPrimitiveField'
      elif type == 'boolean':
        assert not plural, 'plural boolean fields not supported yet'
        funcName = 'printSingularBooleanField'
      elif not nullable and not plural:
        # Special case: singular object fields don't need the value passed.
        print('  fields.printSingularObjectField("%s");' % fieldName)
        continue
      else:
        nullable_str = 'Nullable' if nullable else ''
        plural_str = 'Plural' if plural else 'SingularObject'
        funcName = 'print%s%sField' % (nullable_str, plural_str)

      assert funcName is not None
      print('  fields.%s("%s", node.get%s());' % (
        funcName, fieldName, title(fieldName)))

    if anyFieldIsANode:
      print('''
  endVisitNode(fields.finishPrinting());
}
''')
    else:
      print('''
  printed_.back().emplace_back(fields.finishPrinting());
}
''')

  def start_union(self, name):
    pass

  def union_option(self, option):
    pass

  def end_union(self, name):
    pass
