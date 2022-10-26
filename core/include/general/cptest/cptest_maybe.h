// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __CPTEST_MAYBE_H__
#define __CPTEST_MAYBE_H__

#include "maybe_res.h"
#include "gmock/gmock.h"

namespace testing {

namespace maybe_matcher {

// Matchers for Maybe<T> objects.
// Usage examples:
//   Maybe<int> m = ...;
//   EXPECT_THAT(m, IsValue(3));     // Must hold 3
//   EXPECT_THAT(m, IsValue(_));     // Must be a value
//   EXPECT_THAT(m, IsError("HA"));  // Must be an error with specific text
//   EXPECT_THAT(m, IsError(_));     // Any error (but not a value)

//
// Generic classes that handle either the value or the error
//

// Matcher for Maybe values.
// Verify that Maybe<T>::ok() is as expected, and runs a matcher on the internal value or error.
//
// Abstract base class, inherited to match either the internal value or the error value.
// Template parameters:
//   MaybeType - the Maybe type, possibly with "const &".
//   GetInternal - gets the internal value or error from Maybe.
template <typename MaybeType, typename GetInternal>
class BaseMatcher : public MatcherInterface<MaybeType>
{
private:
    using InternalValue = decltype(GetInternal::get(std::declval<MaybeType>()));

public:
    BaseMatcher(const Matcher<InternalValue> &_matcher)
            :
        label(GetInternal::expected_ok ? "Value" : "Error"),
        matcher(_matcher)
    {
    }

    bool
    MatchAndExplain(MaybeType m, MatchResultListener *listener) const override {
        if (m.ok() != GetInternal::expected_ok) return false;
        return matcher.MatchAndExplain(GetInternal::get(m), listener);
    }

    // LCOV_EXCL_START - Only called when a test fails, to explain why.
    void
    DescribeTo(::std::ostream *os) const override {
        *os << label << "(";
        matcher.DescribeTo(os);
        *os << ")";
    }

    void
    DescribeNegationTo(::std::ostream *os) const override {
        *os << label << "(";
        matcher.DescribeNegationTo(os);
        *os << ")";
    }
    // LCOV_EXCL_STOP

private:
    std::string label;
    Matcher<InternalValue> matcher;
};

// Temporary matcher for Maybe values - converted to BaseMatcher when needed.
// Converts any matcher to a Maybe matcher, which invokes the internal matcher on the value or error.
// Template parameters:
//   InternalMatcherType - Any matcher type that matches the value/error.
//   InternalValueGetter - gets the internal value or error from Maybe.
template <typename InternalMatcherType, typename InternalValueGetter>
class TempMatcher
{
public:
    TempMatcher(InternalMatcherType _matcher) : matcher(_matcher) {}

    // The internal type becomes known when this object is cast to a specific
    //   matcher type. Create a Maybe matcher, while casting the internal matcher to the
    //   type that we now know.
    template <typename MaybeType>
    operator Matcher<MaybeType>() const
    {
        using MaybeMatcherType = BaseMatcher<MaybeType, InternalValueGetter>;
        return MakeMatcher(new MaybeMatcherType(matcher));
    }

private:
    InternalMatcherType matcher;
};

//
// Classes to get the internal value from a Maybe object.
// The internal value can be either the value or the error.
//

class GetValue
{
public:
    static const bool expected_ok = true;

    template<typename T, typename TErr>
    static T
    get(const Maybe<T, TErr> &m)
    {
        return m.unpack();
    }
};

class GetError
{
public:
    static const bool expected_ok = false;

    template<typename T, typename TErr>
    static TErr
    get(const Maybe<T, TErr> &m)
    {
        return m.getErr();
    }
};

} // namespace maybe_matcher

//
// Functions to return matchers - to be used by test code.
//

// Convert Matcher<T> to Matcher<Maybe<T>>, which verifies that it's ok and matches the value.
template<typename MatcherType>
static inline ::testing::maybe_matcher::TempMatcher<MatcherType, ::testing::maybe_matcher::GetValue>
IsValue(MatcherType matcher)
{
    return ::testing::maybe_matcher::TempMatcher<MatcherType, ::testing::maybe_matcher::GetValue>(matcher);
}

// Convert Matcher<TErr> to Matcher<Maybe<T, TErr>>, which verifies that it's not ok and matches the error.
template<typename MatcherType>
static inline ::testing::maybe_matcher::TempMatcher<MatcherType, ::testing::maybe_matcher::GetError>
IsError(MatcherType matcher)
{
    return ::testing::maybe_matcher::TempMatcher<MatcherType, ::testing::maybe_matcher::GetError>(matcher);
}

} // namespace testing

#endif // __CPTEST_MAYBE_H__
