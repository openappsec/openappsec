/**
 * Copyright 2019-present, GraphQL Foundation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
#pragma once

/***
 * This file contains definitions that need to be shared by the parser
 * and the lexer.
 */

yy::GraphQLParserImpl::syntax_error make_error(const yy::location &loc, const std::string &str);

struct LexerExtra {
  std::string str;
  yy::location loc;
};
