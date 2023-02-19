# Copyright 2019-present, GraphQL Foundation
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

def title(s):
  '''Capitalize the first character of s.'''
  return s[0].capitalize() + s[1:]


def camel(s):
  '''Lowercase the first character of s.'''
  return s[0].lower() + s[1:]


def snake(s):
  '''Convert from title or camelCase to snake_case.'''
  if len(s) < 2:
    return s.lower()
  out = s[0].lower()
  for c in s[1:]:
    if c.isupper():
      out += '_'
      c = c.lower()
    out += c
  return out
