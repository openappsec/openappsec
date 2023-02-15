/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "location.hh"

namespace facebook {
namespace graphql {
namespace ast {

namespace visitor {
class AstVisitor;
}

class Node {
  yy::location location_;
public:
  explicit Node(const yy::location &location)
    : location_(location) {}

  virtual ~Node() {}

  const yy::location &getLocation() const
  { return location_; }

  virtual void accept(visitor::AstVisitor *visitor) const = 0;
};

}
}
}
