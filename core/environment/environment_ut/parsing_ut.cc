#include "cptest.h"
#include "environment_evaluator.h"

using namespace std;
using namespace testing;
using namespace EnvironmentHelper;

static const string error = "EvaluatorParseError not thrown as it should have been! Test Failed.";

TEST(ParsingTest, wrong_param_number_test_range)
{
    try {
        reportWrongNumberOfParams("wrong_param_number_test_range", 4, 1, 3);
    }
    catch (EvaluatorParseError e) {
        string output = e.getError();
        string expected = "Wrong number of parameters for 'wrong_param_number_test_range'. "
            "Got 4 parameters instead of expected between 1 and 3";
        EXPECT_EQ(output, expected);
        return;
    }
    ADD_FAILURE() << error;
}

TEST(ParsingTest, wrong_param_number_test_min_eq_max)
{
    try {
        reportWrongNumberOfParams("wrong_param_number_test_min_eq_max", 0, 1, 1);
    }
    catch (EvaluatorParseError e) {
        string output = e.getError();
        string expected = "Wrong number of parameters for 'wrong_param_number_test_min_eq_max'. "
            "Got 0 parameters instead of expected 1";
        EXPECT_EQ(output, expected);
        return;
    }
    ADD_FAILURE() << error;
}

TEST(ParsingTest, wrong_param_number_test_too_few)
{
    try {
        reportWrongNumberOfParams("wrong_param_number_test_too_few", 0, 2, -1);
    }
    catch (EvaluatorParseError e) {
        string output = e.getError();
        string expected = "Wrong number of parameters for 'wrong_param_number_test_too_few'. "
            "Got 0 parameters instead of expected more than 2";
        EXPECT_EQ(output, expected);
        return;
    }
    ADD_FAILURE() << error;
}

TEST(ParsingTest, wrong_param_type_test)
{
    try {
        reportWrongParamType("wrong_param_type_test", "bad_param", "good_reason");
    }
    catch (EvaluatorParseError e) {
        string output = e.getError();
        string expected = "Parameter 'bad_param' for 'wrong_param_type_test' is of the "
            "wrong type because: good_reason";
        EXPECT_EQ(output, expected);
        return;
    }
    ADD_FAILURE() << error;
}

TEST(ParsingTest, unkown_evaluator_type_test)
{
    try {
        reportUnknownEvaluatorType("bad_eval");
    }
    catch (EvaluatorParseError e) {
        string output = e.getError();
        string expected = "Evaluator 'bad_eval' doesn't exist for the required type";
        EXPECT_EQ(output, expected);
        return;
    }
    ADD_FAILURE() << error;
}

TEST(ParsingTest, break_to_params_test_empty_input)
{
    vector<string> res;
    EXPECT_EQ(breakEvaluatorString("()").second, res);
}

TEST(ParsingTest, break_to_params_test_single_in)
{
    vector<string> res = { "(X)" };
    EXPECT_EQ(breakEvaluatorString("((X))").second, res);
}

TEST(ParsingTest, break_to_params_common_use)
{
    vector<string> res = { "a", "1234 asd", "((1+2)*3)" };
    EXPECT_EQ(breakEvaluatorString("(a , 1234 asd ,((1+2)*3))").second, res);
}

TEST(ParsingTest, break_to_params_test_commas_and_ignore_spaces)
{
    vector<string> res = { "", "", "" };
    EXPECT_EQ(breakEvaluatorString("(,, ,     )").second, res);
}

TEST(ParsingTest, break_to_params_bracket_games)
{
    vector<string> res = { ") ,x x(()", ")))," };
    EXPECT_EQ(breakEvaluatorString("() ,x x((),))),)").second, res);
}

TEST(ParsingTest, break_evaluator_string_test_empty_legal_input)
{
    string normalized = "()";
    auto pair = breakEvaluatorString(normalized);
    string s = "";
    vector<string> v;

    EXPECT_EQ(pair, make_pair(s, v));
}

TEST(ParsingTest, break_evaluator_string_test_legal_input)
{
    string normalized = "CMD((3 + 3 ) * 7 (),  abc)";
    auto pair = breakEvaluatorString(normalized);
    string s = "CMD";
    vector<string> v = { "(3 + 3 ) * 7 ()", "abc" };

    EXPECT_EQ(pair, make_pair(s, v));
}

TEST(ParsingTest, break_evaluator_string_test_no_open_bracket)
{
    try {
        breakEvaluatorString("EVALUATOR)");
    }
    catch (EvaluatorParseError e) {
        EXPECT_EQ(e.getError(), "Could not find the opening bracket in the string");
        return;
    }
    ADD_FAILURE() << error;
}

TEST(ParsingTest, break_evaluator_string_test_no_close_bracket)
{
    try {
        breakEvaluatorString("EVALUATOR(x+1 = 3");
    }
    catch (EvaluatorParseError e) {
        EXPECT_EQ(e.getError(), "Could not find the closing bracket in the string");
        return;
    }
    ADD_FAILURE() << error;
}
