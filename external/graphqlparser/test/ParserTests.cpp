/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "Ast.h"
#include "GraphQLParser.h"
#include "c/GraphQLAstToJSON.h"

using namespace facebook::graphql;
using namespace facebook::graphql::ast;


static void expectError(const char *queryStr, const char *expectedError) {
  const char *actualError = nullptr;
  auto ast = parseString(queryStr, &actualError);

  EXPECT_FALSE(ast);
  EXPECT_STREQ(actualError, expectedError);

  std::free((void *)actualError);
}

static void expectSuccessImpl(const char *queryStr, bool enableSchema) {
  const char *actualError = nullptr;
  auto ast = enableSchema
    ? parseStringWithExperimentalSchemaSupport(queryStr, &actualError)
    : parseString(queryStr, &actualError);

  EXPECT_TRUE(ast != nullptr);
  EXPECT_STREQ(nullptr, actualError);

  std::free((void *)actualError);  // NOLINT
}

static void expectSuccess(const char *queryStr) {
  expectSuccessImpl(queryStr, false);
}

static void expectSchemaSuccess(const char *queryStr) {
  expectSuccessImpl(queryStr, true);
}

static void checkSimpleError() {
  expectError("query myquery on type { field }",
              "1.15-16: syntax error, unexpected on, expecting ( or @ or {");
}

TEST(ParserTests, RejectsUnrecognizedCharacter) {
  expectError("query myquery { field };",
              "1.24: unrecognized character ;");
}

TEST(ParserTests, RejectsControlCharacter) {
  expectError("query myQuery { \a }",
              R"(1.17: unrecognized character \a)");
}

TEST(ParserTests, AcceptsUnicodeBOM) {
  expectSuccess("\xef\xbb\xbfquery myquery { field }");
  expectSuccess("query myquery\xef\xbb\xbf{ field }");
}

TEST(ParserTests, ReportsErrorLocationAfterIgnoredBOM) {
  expectError("\xef\xbb\xbfquery myquery { field };",
              "1.27: unrecognized character ;");

}

TEST(ParserTests, RejectsPartialBOM) {
  expectError("\xefquery myquery { field };",
              R"(1.1: unrecognized character \xef)");
}

TEST(ParserTests, RejectsVerticalTab) {
  expectError("\v", R"(1.1: unrecognized character \v)");
}

TEST(ParserTests, RejectsFormFeed) {
  expectError("\f", R"(1.1: unrecognized character \f)");
}

TEST(ParserTests, RejectsNoBreakSpace) {
  expectError("\xa0", R"(1.1: unrecognized character \xa0)");
}


TEST(ParserTests, LocationTracking) {
  SCOPED_TRACE("LocationTracking");
  checkSimpleError();
}

TEST(ParserTests, LocationTrackingResetsAcrossInputs) {
  {
    SCOPED_TRACE("LocationTrackingResetsAcrossInputsFirstTime");
    checkSimpleError();
  }

  {
    SCOPED_TRACE("LocationTrackingResetsAcrossInputsSecondTime");
    checkSimpleError();
  }

}

TEST(ParserTests, LocationTrackingCollapsesCRLF) {
  expectError("\r\n;", "2.1: unrecognized character ;");
}

TEST(ParserTests, AcceptsEmptyString) {
  expectSuccess(R"({ field(arg:"") })");
}

TEST(ParserTests, AcceptsEmptyBlockString) {
  expectSuccess(R"({ field(arg:"""""") })");
}

TEST(ParserTests, UnterminatedString) {
  expectError("\"", "1.1: Unterminated string at EOF");
  expectError("\"\n\"", "1.1-2: Unterminated string");
}

TEST(ParserTests, RejectControlCharacterInString) {
  expectError("{ field(arg:\"\b\") }", R"(1.13-14: unrecognized character \b)");
}

TEST(ParserTests, RejectsBadXEscapeSequence) {
  expectError(R"({ field(arg:"\x") })", R"(1.13-15: bad escape sequence \x)");
}

TEST(ParserTests, RejectsIncompleteUnicodeEscape) {
  expectError(R"({ field(arg:"\u1") })", "1.13-15: bad Unicode escape sequence");
}

TEST(ParserTests, RejectsUnicodeEscapeWithBadChars) {
  expectError(R"({ field(arg:"\u0XX1") })", "1.13-15: bad Unicode escape sequence");
  expectError(R"({ field(arg:"\uXXXX") })", "1.13-15: bad Unicode escape sequence");
  expectError(R"({ field(arg:"\uFXXX") })", "1.13-15: bad Unicode escape sequence");
  expectError(R"({ field(arg:"\uXXXF") })", "1.13-15: bad Unicode escape sequence");
}

TEST(ParserTests, AcceptsValidUnicodeEscape) {
  const char *actualError = nullptr;
  auto ast = parseString(R"({ field(arg:"\u0009Hello") })", &actualError);

  EXPECT_TRUE(ast != nullptr);
  EXPECT_STREQ(nullptr, actualError);
  std::free((void *)actualError);

  auto doc = dynamic_cast<Document *>(ast.get());
  ASSERT_TRUE(doc != nullptr);

  const auto& defs = doc->getDefinitions();
  ASSERT_EQ(1, defs.size());

  auto opDef = dynamic_cast<OperationDefinition *>(defs[0].get());
  ASSERT_TRUE(opDef != nullptr);

  ASSERT_EQ(1, opDef->getSelectionSet().getSelections().size());

  auto field = dynamic_cast<Field *>(opDef->getSelectionSet().getSelections()[0].get());
  ASSERT_TRUE(field != nullptr);

  auto *args = field->getArguments();
  ASSERT_NE(nullptr, args);
  ASSERT_EQ(1, args->size());
  auto *val = dynamic_cast<const StringValue *>(&(*args)[0]->getValue());
  ASSERT_NE(nullptr, val);
  EXPECT_STREQ("\tHello", val->getValue());
}

TEST(ParserTests, TracksLocationAcrossStrings) {
  expectError(R"({ field(arg:"\uFEFF\n") };)",
              "1.26: unrecognized character ;");
}

TEST(ParserTests, UsefulErrors) {
  expectError("{ ...MissingOn }\nfragment MissingOn Type",
              "2.20-23: syntax error, unexpected IDENTIFIER, expecting on");

  expectError("{ field: {} }",
              "1.10: syntax error, unexpected {");

  expectError(
    "notanoperation Foo { field }",
    "1.1-14: syntax error, unexpected IDENTIFIER");

  expectError("...",
              "1.1-3: syntax error, unexpected ...");
}

TEST(ParserTests, AcceptsVariableInlineValues) {
  expectSuccess("{ field(complex: { a: { b: [ $var ] } }) }");
}

TEST(ParserTests, RejectsVariablesInConstantValues) {
  expectError("query Foo($x: Complex = { a: { b: [ $var ] } }) { field }",
              "1.37-40: syntax error, unexpected VARIABLE");
}

TEST(ParserTests, RejectsFragmentsNamedOn) {
  expectError("fragment on on on { on }",
              "1.10-11: syntax error, unexpected on");
}

TEST(ParserTests, RejectsFragmentSpreadOfOn) {
  expectError("{ ...on }",
              "1.9: syntax error, unexpected }");
};

TEST(ParserTests, AcceptsNullValue) {
  expectSuccess("{ fieldWithNullableStringInput(input: null) }");
}

TEST(ParserTests, AcceptsSimpleQuery) {
  expectSuccess("query MyQuery { myfield }");
}

TEST(ParserTests, AcceptsSimpleMutation) {
  expectSuccess("mutation MyMut { myfield }");
}

TEST(ParserTests, AcceptsSimpleSubscription) {
  expectSuccess("subscription MySub { myfield }");
}

TEST(ParserTests, AcceptsQueryShorthand) {
  expectSuccess("{ myfield }");
}

TEST(ParserTests, AcceptsLonghandUnnamedQuery) {
  expectSuccess("query { myfield }");
}

TEST(ParserTests, AcceptsLonghandUnnamedMutation) {
  expectSuccess("mutation { myfield }");
}

TEST(ParserTests, AcceptsLonghandUnnamedSubscription) {
  expectSuccess("subscription { myfield }");
}

TEST(ParserTests, AllowsNonKeywordsForNames) {
  const char *nonKeywords[] = {
    "on",
    "fragment",
    "query",
    "mutation",
    "subscription",
    "true",
    "false"
  };

  for (auto keyword : nonKeywords) {
    const char *fragmentName = !strcmp(keyword, "on") ? "a" : keyword;

    std::ostringstream str;

    str << "query " << keyword << "{\n"
        << "  ... " << fragmentName << '\n'
        << "  ... on " << keyword << " { field }\n"
        << "}\n"
        << "fragment " << fragmentName << " on Type {"
        << "  " << keyword << '(' << keyword << ": $" << keyword << ") @" << keyword << '(' << keyword << ": " << keyword << ")\n"
        << "}\n";
    expectSuccess(str.str().c_str());
  }
}

static void testCorrectOutputForStockFile(
    const char *inputFileName,
    const char *outputFileName,
    bool withSchemaParsing) {
  FILE *fp = fopen(inputFileName, "r");
  ASSERT_NE(nullptr, fp);
  const char *error = nullptr;
  std::unique_ptr<Node> ast;
  if (withSchemaParsing) {
    ast = parseFileWithExperimentalSchemaSupport(fp, &error);
  } else {
    ast = parseFile(fp, &error);
  }
  ASSERT_TRUE(ast);
  ASSERT_FALSE(error);
  fclose(fp);

  const char *json = graphql_ast_to_json((const struct GraphQLAstNode *)ast.get());
  std::ifstream ifs(outputFileName);
  std::stringstream ss;
  ss << ifs.rdbuf();
  EXPECT_STREQ(
    json,
    ss.str().c_str()
  );
  free((void *)json);
}

TEST(ParserTests, ProducesCorrectOutputForKitchenSink) {
  SCOPED_TRACE("KitchenSink");
  testCorrectOutputForStockFile(
    "test/kitchen-sink.graphql",
    "test/kitchen-sink.json",
    false);
}

TEST(ParserTests, ProducesCorrectOutputForSchemaKitchenSink) {
  SCOPED_TRACE("SchemaKitchenSink");
  testCorrectOutputForStockFile(
    "test/schema-kitchen-sink.graphql",
    "test/schema-kitchen-sink.json",
    true);
}

static void expectSchemaParsing(const char *queryStr) {
  char buf[strlen("1.1-XXX: schema support disabled") + 1];
  ASSERT_LT(strlen(queryStr), 999);
  snprintf(
    buf,
    sizeof(buf),
    "1.1-%lu: schema support disabled",
    strlen(queryStr));
  expectError(queryStr, buf);
  expectSchemaSuccess(queryStr);
}

#define DIRECTIVES "@d1(a: 1) @d2(a: 2)"

TEST(SchemaParserTests, SimpleSchema) {
  expectSchemaParsing(
    "schema " DIRECTIVES " { query: QueryType, mutation: MutType }");
  expectSchemaParsing("scalar SomeScalar " DIRECTIVES);
  expectSchemaParsing("type SomeObject implements SomeInterface " DIRECTIVES
                      " { someField : SomeType }");
  expectSchemaParsing("interface SomeInterface " DIRECTIVES
                      " { someField : SomeType }");
  expectSchemaParsing("union SomeUnion " DIRECTIVES
                      " = SomeType | SomeOtherType");
  expectSchemaParsing("enum SomeEnum " DIRECTIVES " { VALUE, OTHER_VALUE }");
  expectSchemaParsing("input SomeInput " DIRECTIVES "{ someField: SomeType, "
                      "otherField: otherType }");
  expectSchemaParsing("extend type SomeType " DIRECTIVES
                      "{ anotherField : AnotherType }");
  expectSchemaParsing("directive @somedirective(a1 : t1 = 1 " DIRECTIVES
                      ", a2 : t2) on foo | bar");
}
