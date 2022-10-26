#include "virtual_modifiers.h"

#include "cptest.h"

using namespace std;

TEST(SingleModifer, CharRemover)
{
    string orig = "   123  45 67  ggg\t h  ";

    auto without_space = makeVirtualContainer<CharRemover<' '>>(orig);
    auto without_tab = makeVirtualContainer<CharRemover<'\t'>>(orig);
    auto without_g = makeVirtualContainer<CharRemover<'g'>>(orig);
    auto withall = makeVirtualContainer<CharRemover<'p'>>(orig);

    EXPECT_EQ(orig, "   123  45 67  ggg\t h  ");
    EXPECT_EQ(string(without_space.begin(), without_space.end()), "1234567ggg\th");
    EXPECT_EQ(string(without_tab.begin(), without_tab.end()), "   123  45 67  ggg h  ");
    EXPECT_EQ(string(without_g.begin(), without_g.end()), "   123  45 67  \t h  ");
    EXPECT_EQ(string(withall.begin(), withall.end()), orig);
}

TEST(SingleModifer, HexDecoder)
{
    string orig = "%45 %46 x47 %4";

    auto decode_cent = makeVirtualContainer<HexDecoder<'%'>>(orig);
    auto decode_x = makeVirtualContainer<HexDecoder<'x'>>(orig);

    EXPECT_EQ(orig, "%45 %46 x47 %4");
    EXPECT_EQ(string(decode_cent.begin(), decode_cent.end()), "E F x47 %4");
    EXPECT_EQ(string(decode_x.begin(), decode_x.end()), "%45 %46 G %4");

    orig = "452e462E47";
    auto decode_all = makeVirtualContainer<HexDecoder<-1>>(orig);
    EXPECT_EQ(string(decode_all.begin(), decode_all.end()), "E.F.G");
}

TEST(SingleModifer, ReplaceChar)
{
    string orig = "12+34-56-78+90-12-34+56";

    auto plus_to_space = makeVirtualContainer<ReplaceChar<'+', ' '>>(orig);
    auto minus_to_plus = makeVirtualContainer<ReplaceChar<'-', '+'>>(orig);
    auto plus_to_minus = makeVirtualContainer<ReplaceChar<'+', '-'>>(orig);
    auto minus_to_space = makeVirtualContainer<ReplaceChar<'-', ' '>>(orig);
    auto m_to_n = makeVirtualContainer<ReplaceChar<'m', 'n'>>(orig);

    EXPECT_EQ(orig, "12+34-56-78+90-12-34+56");
    EXPECT_EQ(string(plus_to_space.begin(), plus_to_space.end()), "12 34-56-78 90-12-34 56");
    EXPECT_EQ(string(minus_to_plus.begin(), minus_to_plus.end()), "12+34+56+78+90+12+34+56");
    EXPECT_EQ(string(plus_to_minus.begin(), plus_to_minus.end()), "12-34-56-78-90-12-34-56");
    EXPECT_EQ(string(minus_to_space.begin(), minus_to_space.end()), "12+34 56 78+90 12 34+56");
    EXPECT_EQ(string(m_to_n.begin(), m_to_n.end()), orig);
}

class ReplaceOne : public ReplaceSubContiners<string>
{
public:
    ReplaceOne() { init(&src, &dst); }

private:
    string src = "111";
    string dst = "222";
};

class ReplaceTwo : public ReplaceSubContiners<string>
{
public:
    ReplaceTwo() { init(&src, &dst); }

private:
    string src = "333";
    string dst = "4444";
};

class ReplaceThree : public ReplaceSubContiners<string>
{
public:
    ReplaceThree() { init(&src, &dst); }

private:
    string src = "555";
    string dst = "44";
};

TEST(SingleModifer, ReplaceSubContiners)
{
    string orig = "111 333 11 555 1111";

    auto replace_one = makeVirtualContainer<ReplaceOne>(orig);
    auto replace_two = makeVirtualContainer<ReplaceTwo>(orig);
    auto replace_three = makeVirtualContainer<ReplaceThree>(orig);

    EXPECT_EQ(orig, "111 333 11 555 1111");
    EXPECT_EQ(string(replace_one.begin(), replace_one.end()), "222 333 11 555 2221");
    EXPECT_EQ(string(replace_two.begin(), replace_two.end()), "111 4444 11 555 1111");
    EXPECT_EQ(string(replace_three.begin(), replace_three.end()), "111 333 11 44 1111");
}

TEST(MultipleModifier, TwoModifiers)
{
    string orig = " 4 5 2 e 4 6 2 E 4 7 ";
    auto decode_one = makeVirtualContainer<CharRemover<' '>>(orig);
    auto decode_two = makeVirtualContainer<HexDecoder<-1>>(decode_one);
    EXPECT_EQ(string(decode_two.begin(), decode_two.end()), "E.F.G");
}

using CombinedModifier = ModifiersAggregator<HexDecoder<-1>, CharRemover<' '>>;

TEST(MultipleModifier, CombinedModifier)
{
    string orig = " 4 5 2 e 4 6 2 E 4 7 ";
    auto decode = makeVirtualContainer<CombinedModifier>(orig);
    EXPECT_EQ(string(decode.begin(), decode.end()), "E.F.G");
}
