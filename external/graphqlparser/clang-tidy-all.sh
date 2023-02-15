#!/bin/sh
# Copyright 2019-present, GraphQL Foundation
find . -name '*.cpp' | grep -v lexer | grep -v googletest | grep -v tab.cpp | xargs clang-tidy -p build
