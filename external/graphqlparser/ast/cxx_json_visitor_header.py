# Copyright 2019-present, GraphQL Foundation
# All rights reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from casing import title
from license import C_LICENSE_COMMENT

class Printer(object):
  def __init__(self):
    self._anyFieldIsANode = False

  def start_file(self):
    print(C_LICENSE_COMMENT + '/** @generated */')

  def end_file(self):
    pass

  def start_type(self, name):
    self._anyFieldIsANode = False

  def end_type(self, name):
    titleName = title(name)
    if self._anyFieldIsANode:
      print('bool visit%s(const %s &node) override;' % (titleName, titleName))
    print('void endVisit%s(const %s &node) override;' % (titleName, titleName))
    print()

  def field(self, type, name, nullable, plural):
    if (not self._anyFieldIsANode and
        type not in ('OperationKind', 'string', 'boolean')):
      self._anyFieldIsANode = True

  def start_union(self, name):
    pass

  def union_option(self, option):
    pass

  def end_union(self, name):
    pass
