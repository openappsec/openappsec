/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "AstNode.h"
#include "AstVisitor.h"

#include <sstream>
#include <vector>

namespace facebook {
namespace graphql {
namespace ast {
namespace visitor {

/**
 * Produces a JSON string describing the visited AST, in a format that
 * would be a valid graphql-js AST when parsed.
 */
class JsonVisitor : public AstVisitor {
 private:
  using ChildrenList = std::vector<std::string>;
  // Stack of lists of printed children.
  // Postvisit method precondition: printed.back() contains strings
  // for this node's children.
  // Postvisit method postcondition: *(printed.rbegin() - 1) has had this
  std::vector<ChildrenList> printed_;

  // Interface to print fields for each kind of node.
  // Note that, because of the post-order traversal for printing,
  // field values need not be passed explicitly; they are grabbed from
  // the passed-in visitor!
  class NodeFieldPrinter {
   private:
    JsonVisitor &visitor_;
    ChildrenList::const_iterator nextChild_;
    std::ostringstream out_;

    void printFieldSeparator();

    // Prints a non-null array of n children from the given
    // iterator. Does not update the iterator.
    void printChildList(
      std::ostringstream &out,
      const std::vector<std::string>::const_iterator &childIterator,
      size_t numChildren);

    void printLocation(std::ostringstream &out, const yy::location &location);

   public:
    // Begin printing the fields for a node of the given kind at the
    // given location.
    NodeFieldPrinter(
      JsonVisitor &visitor,
      const char *nodeKind,
      const Node &node);

    std::string finishPrinting();

    void printSingularPrimitiveField(const char *fieldName, const char *value);
    void printSingularBooleanField(const char *fieldName, bool value);
    void printSingularObjectField(const char *fieldName);
    void printNullableSingularObjectField(const char *fieldName, const void *value);

    template <typename T>
      void printPluralField(
        const char *fieldName,
        const std::vector<std::unique_ptr<T>> &value) {
      printFieldSeparator();
      out_ << '"' << fieldName << "\":";
      printChildList(out_, nextChild_, value.size());
      nextChild_ += value.size();
    }

    template <typename T>
    void printNullablePluralField(
        const char *fieldName,
        const std::vector<std::unique_ptr<T>> *value) {
      printFieldSeparator();
      out_ << '"' << fieldName << "\":";
      if (value == nullptr) {
        out_ << "null";
      } else {
        printChildList(out_, nextChild_, value->size());
        nextChild_ += value->size();
      }
    }
  };

  // Must be called at the start of all visit methods for node types
  // that have children. Maintains printed_.
  void visitNode();

  // Must be called at the end of all visit methods for node types
  // that have children, passing the text for this node. Maintains
  // printed_.
  void endVisitNode(std::string &&str);

  // Prints one of the many FooValue types that is prepresented with a
  // single string.
  template <typename ValueNode>
  void endVisitValueRepresentedAsString(const char *valueKind, const ValueNode &value);

public:
  JsonVisitor();
  ~JsonVisitor() {}

  std::string getResult() const;

  #include "JsonVisitor.h.inc"
};

}
}
}
}
