/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "position.hh"
#include "JsonVisitor.h"

#include <cassert>
#include <iterator>

namespace facebook {
namespace graphql {
namespace ast {
namespace visitor {

static std::string escape(const char *s) {
  static char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  std::string result;
  while (unsigned char ch = *s++) {
    if (ch >= '\0' && ch <= '\x1f') {
      result.push_back('\\');
      result.push_back('u');
      result.push_back('0');
      result.push_back('0');
      result.push_back(ch >= 16 ? '1' : '0');
      result.push_back(hex[ch % 16]);
    } else if (ch == '"') {
      result.push_back('\\');
      result.push_back('"');
    } else if (ch == '\\') {
      result.push_back('\\');
      result.push_back('\\');
    } else {
      result.push_back(ch);
    }
  }
  return result;
}

JsonVisitor::NodeFieldPrinter::NodeFieldPrinter(
    JsonVisitor &visitor,
    const char *nodeKind,
    const Node &node)
    : visitor_(visitor)
{
  if (!visitor_.printed_.empty()) {
    nextChild_ = visitor_.printed_.back().begin();
  }
  // NOTE: If you're an Emacs user and this file's use of C++11 raw
  // strings doesn't highlight correctly in c++-mode, try upgrading to
  // Emacs 26 if you can.
  out_ << R"({"kind":")" << nodeKind << R"(","loc":)";
  printLocation(out_, node.getLocation());
}

std::string JsonVisitor::NodeFieldPrinter::finishPrinting() {
  assert(!out_.str().empty());
  out_ << '}';
  auto result(out_.str());
#ifndef NDEBUG
  out_.str("");
#endif
  return result;

}

void JsonVisitor::NodeFieldPrinter::printFieldSeparator()
{
  out_ << ',';
}

void JsonVisitor::NodeFieldPrinter::printSingularPrimitiveField(
    const char *fieldName,
    const char *value) {
  printFieldSeparator();
  out_ << '"' << fieldName << R"(":)";
  out_ << '"' << escape(value) << '"';
}

void JsonVisitor::NodeFieldPrinter::printSingularBooleanField(
    const char *fieldName,
    bool value) {
  printFieldSeparator();
  out_ << '"' << fieldName << R"(":)";
  out_ << (value ? "true" : "false");
}

void JsonVisitor::NodeFieldPrinter::printSingularObjectField(const char *fieldName) {
  printFieldSeparator();
  out_ << '"' << fieldName << R"(":)";
  assert(!visitor_.printed_.empty());
  out_ << *nextChild_++;
}

void JsonVisitor::NodeFieldPrinter::printNullableSingularObjectField(
    const char *fieldName,
    const void *value) {
  printFieldSeparator();
  out_ << '"' << fieldName << R"(":)";
  if (value != nullptr) {
    assert(!visitor_.printed_.empty());
    out_ << *nextChild_++;
  } else {
    out_ << "null";
  }
}

// Method invariant: printed_ contains strings for this node's children.
void JsonVisitor::NodeFieldPrinter::printLocation(
    std::ostringstream &out,
    const yy::location &location)
{
  out << R"({"start": {"line": )" << location.begin.line
       << R"(,"column":)" << location.begin.column
       << R"(}, "end": {"line":)" << location.end.line
       << R"(,"column":)" << location.end.column
       << "}}";
}

void JsonVisitor::NodeFieldPrinter::printChildList(
    std::ostringstream &out,
    const std::vector<std::string>::const_iterator &childIterator,
    size_t numChildren) {
  out << '[';
  for (size_t ii = 0; ii < numChildren; ++ii) {
    if (ii != 0) {
      out << ',';
    }
    out << *(childIterator + ii);
  }
  out << ']';
}

JsonVisitor::JsonVisitor() {
  printed_.emplace_back();
}

void JsonVisitor::visitNode() {
  printed_.emplace_back();
}

void JsonVisitor::endVisitNode(std::string &&str) {
  printed_.pop_back();
  printed_.back().emplace_back(std::move(str));
}

std::string JsonVisitor::getResult() const {
  assert(printed_.size() == 1);
  assert(printed_[0].size() == 1);
  return printed_[0][0];
}

#include "JsonVisitor.cpp.inc"

}  // namespace visitor
}  // namespace ast
}  // namespace graphql
}  // namespace facebook
