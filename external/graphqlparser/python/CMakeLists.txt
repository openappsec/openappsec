
IF (CTYPESGEN_FOUND)
  ADD_CUSTOM_COMMAND(
    OUTPUT GraphQLParser.py
    COMMAND ctypesgen.py ${CMAKE_CURRENT_SOURCE_DIR}/../c/*.h ${CMAKE_CURRENT_BINARY_DIR}/../c/*.h -o ${CMAKE_CURRENT_SOURCE_DIR}/GraphQLParser.py -I ${CMAKE_CURRENT_SOURCE_DIR}/.. -I ${CMAKE_CURRENT_BINARY_DIR}/.. -l graphqlparser -L ${CMAKE_CURRENT_BINARY_DIR}/.. 2>&1 > /dev/null
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/../c/GraphQLAstForEachConcreteType.h ${CMAKE_CURRENT_BINARY_DIR}/../c/GraphQLAst.h ${CMAKE_CURRENT_SOURCE_DIR}/../c/GraphQLAstNode.h ${CMAKE_CURRENT_SOURCE_DIR}/../c/GraphQLAstVisitor.h ${CMAKE_CURRENT_SOURCE_DIR}/../c/GraphQLParser.h
    )
  ADD_CUSTOM_TARGET(
    graphql-parser-python
    ALL
    DEPENDS GraphQLParser.py)
ELSE()
  MESSAGE(WARNING "ctypesgen.py not found; install with pip or easy_install if you want to run pythontest.py.")
ENDIF()
