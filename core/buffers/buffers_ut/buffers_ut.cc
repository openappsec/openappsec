#include <string>

#include "cereal/archives/json.hpp"

#include "cptest.h"
#include "debug.h"
#include "buffer.h"

using namespace std;
using namespace testing;

class BuffersTest : public Test
{
public:
    Buffer
    genBuf(string s1, string s2, string s3)
    {
        Buffer b1(s1), b2(s2), b3(s3);
        return b1 + b2 + b3;
    }
};

TEST_F(BuffersTest, empty_buffer_dump)
{
    Buffer buf;
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(dumpHex(buf), "");
}

TEST_F(BuffersTest, empty_buffer)
{
    Buffer buf;
    EXPECT_EQ(buf.size(), 0u);
}

TEST_F(BuffersTest, basic_content_string)
{
    Buffer buf("123456789");
    EXPECT_EQ(buf.size(), 9u);
    EXPECT_EQ(buf[0], '1');
    EXPECT_EQ(buf[1], '2');
    EXPECT_EQ(buf[2], '3');
    EXPECT_EQ(buf[3], '4');
    EXPECT_EQ(buf[4], '5');
    EXPECT_EQ(buf[5], '6');
    EXPECT_EQ(buf[6], '7');
    EXPECT_EQ(buf[7], '8');
    EXPECT_EQ(buf[8], '9');
}

TEST_F(BuffersTest, basic_content_uchar_vec)
{
    vector<u_char> vec = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    Buffer buf(vec);
    EXPECT_EQ(buf.size(), 9u);
    EXPECT_EQ(buf[0], '1');
    EXPECT_EQ(buf[1], '2');
    EXPECT_EQ(buf[2], '3');
    EXPECT_EQ(buf[3], '4');
    EXPECT_EQ(buf[4], '5');
    EXPECT_EQ(buf[5], '6');
    EXPECT_EQ(buf[6], '7');
    EXPECT_EQ(buf[7], '8');
    EXPECT_EQ(buf[8], '9');
}

TEST_F(BuffersTest, basic_content_char_vec)
{
    vector<char> vec = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    Buffer buf(vec);
    EXPECT_EQ(buf.size(), 9u);
    EXPECT_EQ(buf[0], '1');
    EXPECT_EQ(buf[1], '2');
    EXPECT_EQ(buf[2], '3');
    EXPECT_EQ(buf[3], '4');
    EXPECT_EQ(buf[4], '5');
    EXPECT_EQ(buf[5], '6');
    EXPECT_EQ(buf[6], '7');
    EXPECT_EQ(buf[7], '8');
    EXPECT_EQ(buf[8], '9');
}

TEST_F(BuffersTest, compare)
{
    Buffer buf1("123456789");
    Buffer buf2("123456789");
    EXPECT_TRUE(buf1 == buf2);
    EXPECT_FALSE(buf1 != buf2);
    EXPECT_FALSE(buf1 < buf2);
    EXPECT_TRUE(buf1 <= buf2);
    EXPECT_FALSE(buf1 > buf2);
    EXPECT_TRUE(buf1 >= buf2);

    Buffer buf3("12345678");
    EXPECT_FALSE(buf1 == buf3);
    EXPECT_TRUE(buf1 != buf3);
    EXPECT_FALSE(buf1 < buf3);
    EXPECT_TRUE(buf3 < buf1);
    EXPECT_FALSE(buf1 <= buf3);
    EXPECT_TRUE(buf3 <= buf1);
    EXPECT_TRUE(buf1 > buf3);
    EXPECT_FALSE(buf3 > buf1);
    EXPECT_TRUE(buf1 >= buf3);
    EXPECT_FALSE(buf3 >= buf1);

    Buffer buf4("1234*6789");
    EXPECT_FALSE(buf1 == buf4);
    EXPECT_TRUE(buf1 != buf4);
    EXPECT_FALSE(buf1 < buf4);
    EXPECT_TRUE(buf4 < buf1);
    EXPECT_FALSE(buf1 <= buf4);
    EXPECT_TRUE(buf4 <= buf1);
    EXPECT_TRUE(buf1 > buf4);
    EXPECT_FALSE(buf4 > buf1);
    EXPECT_TRUE(buf1 >= buf4);
    EXPECT_FALSE(buf4 >= buf1);

    Buffer buf5("1234067890");
    EXPECT_FALSE(buf1 == buf5);
    EXPECT_TRUE(buf1 != buf5);
    EXPECT_TRUE(buf1 < buf5);
    EXPECT_FALSE(buf5 < buf1);
    EXPECT_TRUE(buf1 <= buf5);
    EXPECT_FALSE(buf5 <= buf1);
    EXPECT_FALSE(buf1 > buf5);
    EXPECT_TRUE(buf5 > buf1);
    EXPECT_FALSE(buf1 >= buf5);
    EXPECT_TRUE(buf5 >= buf1);

    Buffer buf6("");
    EXPECT_FALSE(buf1 < buf6);
    EXPECT_TRUE(buf6 < buf1);
    EXPECT_FALSE(buf1 <= buf6);
    EXPECT_TRUE(buf6 <= buf1);
    EXPECT_TRUE(buf1 > buf6);
    EXPECT_FALSE(buf6 > buf1);
    EXPECT_TRUE(buf1 >= buf6);
    EXPECT_FALSE(buf6 >= buf1);

    Buffer buf7("");
    EXPECT_FALSE(buf7 < buf6);
    EXPECT_FALSE(buf6 < buf7);
    EXPECT_TRUE(buf7 <= buf6);
    EXPECT_TRUE(buf6 <= buf7);
    EXPECT_FALSE(buf7 > buf6);
    EXPECT_FALSE(buf6 > buf7);
    EXPECT_TRUE(buf7 >= buf6);
    EXPECT_TRUE(buf6 >= buf7);

}

TEST_F(BuffersTest, truncate_head)
{
    Buffer buf("123456789");
    buf.truncateHead(6);
    EXPECT_EQ(buf, Buffer("789"));
}

TEST_F(BuffersTest, truncate_tail)
{
    Buffer buf("123456789");
    buf.truncateTail(4);
    EXPECT_EQ(buf, Buffer("12345"));
}

TEST_F(BuffersTest, keep_head)
{
    Buffer buf("123456789");
    buf.keepHead(6);
    EXPECT_EQ(buf, Buffer("123456"));
}

TEST_F(BuffersTest, keep_tail)
{
    Buffer buf("123456789");
    buf.keepTail(4);
    EXPECT_EQ(buf, Buffer("6789"));
}

TEST_F(BuffersTest, slicing_final)
{
    Buffer buf("123456789");
    Buffer b1 = buf, b2 = buf;
    b1.truncateHead(3); // "456789"
    b1.truncateTail(3); // "456"
    b2.truncateTail(3); // "123456"
    b2.truncateHead(3); // "456"
    EXPECT_EQ(b1, b2);
    b2.truncateHead(1); // "45"
    EXPECT_NE(b1, b2);
}

TEST_F(BuffersTest, data)
{
    Buffer buf("123456789");
    EXPECT_EQ(bcmp(buf.data(), "123456789", 9), 0);
}

struct TestStruct
{
    char first;
    char second;
};

TEST_F(BuffersTest, casting)
{
    Buffer buf("123456789");
    auto test = buf.getTypePtr<struct TestStruct>(2).unpack();
    EXPECT_EQ(test->first, '3');
    EXPECT_EQ(test->second, '4');
}

TEST_F(BuffersTest, casting_fail)
{
    Buffer buf("123456789");
    auto test = buf.getTypePtr<struct TestStruct>(8);
    EXPECT_THAT(test, IsError("Cannot get internal pointer beyond the buffer limits"));
    test = buf.getTypePtr<struct TestStruct>(-1);
    EXPECT_THAT(test, IsError("Invalid length ('start' is not smaller than 'end')"));
    test = buf.getTypePtr<struct TestStruct>(9);
    EXPECT_THAT(test, IsError("Cannot get internal pointer beyond the buffer limits"));
}

TEST_F(BuffersTest, death_on_asserts)
{
    cptestPrepareToDie();

    Buffer buf1("123456789");
    EXPECT_DEATH(buf1[10], "Buffer::operator returned: attempted an access outside the buffer");
    EXPECT_DEATH(buf1[-1], "Buffer::operator returned: attempted an access outside the buffer");
    EXPECT_DEATH(buf1.truncateHead(10), "Cannot set a new start of buffer after the buffer's end");
    EXPECT_DEATH(buf1.truncateTail(10), "Cannot set a new end of buffer after the buffer's end");
    EXPECT_DEATH(buf1.keepHead(10), "Cannot set a new end of buffer before the buffer's start");
    EXPECT_DEATH(buf1.keepTail(10), "Cannot set a new start of buffer after the buffer's end");
}

TEST_F(BuffersTest, basic_content2)
{
    auto buf = genBuf("123", "456", "789");
    EXPECT_EQ(buf.size(), 9u);
    EXPECT_EQ(buf[0], '1');
    EXPECT_EQ(buf[1], '2');
    EXPECT_EQ(buf[2], '3');
    EXPECT_EQ(buf[3], '4');
    EXPECT_EQ(buf[4], '5');
    EXPECT_EQ(buf[5], '6');
    EXPECT_EQ(buf[6], '7');
    EXPECT_EQ(buf[7], '8');
    EXPECT_EQ(buf[8], '9');
}

TEST_F(BuffersTest, compare_buffers)
{
    auto buf1 = genBuf("123", "456", "789");
    auto buf2 = genBuf("12", "3456", "789");
    EXPECT_TRUE(buf1 == buf2);
    EXPECT_FALSE(buf1 != buf2);

    auto buf3 = genBuf("123", "46", "789");
    EXPECT_FALSE(buf1 == buf3);
    EXPECT_TRUE(buf1 != buf3);

    auto buf4 = genBuf("123", "406", "789");
    EXPECT_FALSE(buf1 == buf4);
    EXPECT_TRUE(buf1 != buf4);

    auto buf5 = genBuf("123", "456", "7890");
    EXPECT_FALSE(buf1 == buf5);
    EXPECT_TRUE(buf1 != buf5);
}

TEST_F(BuffersTest, truncate_head2)
{
    auto buf = genBuf("123", "456", "789");
    buf.truncateHead(5);
    EXPECT_EQ(buf, Buffer("6789"));
}

TEST_F(BuffersTest, truncate_tail2)
{
    auto buf = genBuf("123", "456", "789");
    buf.truncateTail(4);
    EXPECT_EQ(buf, Buffer("12345"));
}

TEST_F(BuffersTest, sub_buffer)
{
    auto origbuf = genBuf("123", "456", "789");
    auto subbuf = origbuf.getSubBuffer(4, 7);
    EXPECT_EQ(subbuf, Buffer("567"));
}

TEST_F(BuffersTest, add_compound)
{
    auto buf = genBuf("1", "2", "3");
    // Testing adding a buffer to itself, which is an extreme case.
    buf += buf;
    EXPECT_EQ(buf, Buffer("123123"));
}

string
iterToStr(const Buffer::SegIterator &iter)
{
    return string(reinterpret_cast<const char *>(iter->data()), iter->size());
}

TEST_F(BuffersTest, add_operator_of_iterator)
{
    auto buf = genBuf("12", "3456", "789");
    auto iter = buf.segRange().begin();
    EXPECT_EQ(iterToStr(iter), "12");
    iter++;
    EXPECT_EQ(iterToStr(iter), "3456");
    iter++;
    EXPECT_EQ(iterToStr(iter), "789");
    iter++;
    EXPECT_TRUE(iter == buf.segRange().end());
}

bool
operator==(const vector<string> &vec, const Buffer &buf)
{
    auto vec_iter = vec.begin();
    for (auto &iter : buf.segRange()) {
        if (vec_iter == vec.end()) return false;
        if (iter != *vec_iter) return false;
        vec_iter++;
    }
    return vec_iter == vec.end();
}

bool
operator==(const string &str, const Buffer::Segment &seg)
{
    string tmp(reinterpret_cast<const char *>(seg.data()), seg.size());
    return str == tmp;
}

TEST_F(BuffersTest, iterator_loop)
{
    auto buf = genBuf("12", "3456", "789");
    vector<string> vec = { "12", "3456", "789" };

    auto vec_iter = vec.begin();
    for (auto seg : buf.segRange()) {
        EXPECT_EQ(*vec_iter, seg);
        vec_iter++;
    }
}

TEST_F(BuffersTest, flatten)
{
    auto buf = genBuf("12", "3456", "789");
    EXPECT_EQ((vector<string>{ "12", "3456", "789" }), buf);

    buf.serialize();
    EXPECT_EQ((vector<string>{ "123456789" }), buf);

    auto buf2 = genBuf("12", "3456", "789");
    buf2.truncateHead(1); // "23456789"
    buf2.truncateTail(1); // "2345678"

    buf2.serialize();
    EXPECT_EQ((vector<string>{ "2345678" }), buf2);
}

TEST_F(BuffersTest, get_pointer)
{
    auto buf = genBuf("12", "3456", "789");
    auto ptr1 = buf.getPtr(3, 3);
    ASSERT_TRUE(ptr1.ok());
    // Internal Structure of the buffer didn't change.
    EXPECT_EQ((vector<string>{ "12", "3456", "789" }), buf);
    // Get the currect segment
    auto iter = buf.segRange().begin();
    iter++;
    // Check that the internal pointer points to the segment in the correct location.
    EXPECT_EQ(iter->data() + 1, ptr1.unpack());

    auto ptr2 = buf.getPtr(5, 2);
    ASSERT_TRUE(ptr2.ok());
    // Buffer had to be serialized
    EXPECT_EQ((vector<string>{ "123456789" }), buf);
    // Check that the internal pointer points to the correct point in the serialized data.
    EXPECT_EQ(buf.data() + 5, ptr2.unpack());

    auto ptr3 = buf.getPtr(5, 25);
    EXPECT_THAT(ptr3, IsError("Cannot get internal pointer beyond the buffer limits"));
}

TEST_F(BuffersTest, InternalPtr_assign)
{
    auto buf = genBuf("12", "3456", "789");
    auto ptr1 = buf.getPtr(3, 3);
    ASSERT_TRUE(ptr1.ok());
    auto ptr2 = ptr1;
    ASSERT_TRUE(ptr1.ok());
    ASSERT_TRUE(ptr2.ok());
    EXPECT_EQ(ptr1.unpack(), ptr2.unpack());
}

TEST_F(BuffersTest, InternalPtr_move)
{
    auto buf = genBuf("12", "3456", "789");
    auto ptr1 = buf.getPtr(3, 6);
    ASSERT_TRUE(ptr1.ok());
    auto ptr2 = buf.getPtr(2, 5);
    ASSERT_TRUE(ptr2.ok());
    ptr2 = move(ptr1);
    //Move assignment operator takes over the resources of ptr1.
    EXPECT_EQ(ptr1.unpack(), nullptr);
    ASSERT_TRUE(ptr2.ok());
    EXPECT_EQ(buf.data() + 3, ptr2.unpack());
}

TEST_F(BuffersTest, death_on_asserts2)
{
    cptestPrepareToDie();

    auto buf = genBuf("123", "456", "789");
    EXPECT_DEATH(buf[10], "Buffer::operator returned: attempted an access outside the buffer");
    EXPECT_DEATH(buf[-1], "Buffer::operator returned: attempted an access outside the buffer");
    EXPECT_DEATH(buf.truncateTail(10), "Cannot set a new end of buffer after the buffer's end");
    EXPECT_DEATH(buf.truncateHead(10), "Cannot set a new start of buffer after the buffer's end");
}

TEST_F(BuffersTest, owned_data)
{
    string str("0");
    auto ptr = reinterpret_cast<const u_char *>(str.data());
    Buffer b;
    {
        // OWNED memory copies the memory, so changes to the original pointer don't impact it.
        Buffer c(str.data(), 1, Buffer::MemoryType::OWNED);
        b = c;
        str[0] = '1';
        EXPECT_EQ(Buffer("0"), b);
        EXPECT_NE(ptr, b.data());
    }
    EXPECT_NE(ptr, b.data());
    str[0] = '2';
    EXPECT_EQ(Buffer("0"), b);
}

TEST_F(BuffersTest, static_data)
{
    string str("0");
    auto ptr = reinterpret_cast<const u_char *>(str.data());
    Buffer b;
    {
        // STATIC always points to the original pointer.
        // In real scenarios `str` should be `static const` string and not a local changing varialbe, we absue it in
        // this case specifically so the behavoir of the memory can be shown.
        Buffer c(str.data(), 1, Buffer::MemoryType::STATIC);
        b = c;
        str[0] = '1';
        EXPECT_EQ(Buffer("1"), b);
        EXPECT_EQ(ptr, b.data());
    }
    str[0] = '2';
    EXPECT_EQ(Buffer("2"), b);
}

TEST_F(BuffersTest, volatile_data)
{
    string str("0");
    auto ptr = reinterpret_cast<const u_char *>(str.data());
    Buffer b;
    {
        // VOLATILE memory only pointers to the original pointer while the initial instance lives.
        Buffer c(str.data(), 1, Buffer::MemoryType::VOLATILE);
        b = c;
        str[0] = '1';
        EXPECT_EQ(Buffer("1"), b);
        EXPECT_EQ(ptr, b.data());
    }
    EXPECT_NE(ptr, b.data());
    // Memory was copied, so further changes don't impact it.
    str[0] = '2';
    EXPECT_EQ(Buffer("1"), b);
}

TEST_F(BuffersTest, truncate_volatile_data)
{
    string str("123");
    Buffer b;
    {
        Buffer c(str.data(), 3, Buffer::MemoryType::VOLATILE);
        b = c;
        b.truncateHead(1);
    }
    EXPECT_EQ(Buffer("23"), b);
}

TEST_F(BuffersTest, clear)
{
    auto buf = genBuf("123", "456", "789");
    EXPECT_EQ(buf.size(), 9u);
    buf.clear();
    EXPECT_EQ(buf.size(), 0u);
    Buffer test = buf;
    EXPECT_EQ(test.size(), 0u);
}

TEST_F(BuffersTest, access_after_clear)
{
    auto buf = genBuf("123", "456", "789");
    buf.clear();
    cptestPrepareToDie();
    EXPECT_DEATH(buf[1], "Buffer::operator() returned: attempted an access outside the buffer");
    EXPECT_DEATH(buf[0], "Buffer::operator() returned: attempted an access outside the buffer");
}

TEST_F(BuffersTest, isEmpty)
{
    auto b = genBuf("123", "456", "789");
    EXPECT_FALSE(b.isEmpty());
    b.clear();
    EXPECT_TRUE(b.isEmpty());
    Buffer c = b;
    EXPECT_TRUE(c.isEmpty());
}

TEST_F(BuffersTest, contains)
{
    vector<u_char> vec1 = { '1', '3', '5' };
    auto b1 = Buffer(vec1);

    for (const char ch : vec1) {
        EXPECT_TRUE(b1.contains(ch));
    }

    EXPECT_FALSE(b1.contains('?'));
}

TEST_F(BuffersTest, segmentsNumber)
{
    vector<u_char> vec1 = { '1', '3', '7' };
    vector<u_char> vec2 = { '1', '3', '7' };
    auto b = Buffer(vec1) + Buffer(vec2);
    EXPECT_EQ(b.segmentsNumber(), 2u);
    EXPECT_EQ(b.size(), 6u);
    auto sub_b = b.getSubBuffer(0, 2);
    EXPECT_EQ(sub_b.segmentsNumber(), 1u);
    sub_b.clear();
    EXPECT_EQ(sub_b.segmentsNumber(), 0u);
}

TEST_F(BuffersTest, Equl_buffers)
{
    auto buf = genBuf("123", "456", "789");
    const char* str = "1234567890";
    const u_char* u_str = reinterpret_cast<const u_char *>("1234567890");
    EXPECT_TRUE(buf.isEqual(str, 9));
    EXPECT_FALSE(buf.isEqual(str, 10));
    EXPECT_TRUE(buf.isEqual(u_str, 9));
    EXPECT_FALSE(buf.isEqual(u_str, 10));
}

TEST_F(BuffersTest, string_casting)
{
    auto buf = genBuf("123", "456", "789");
    EXPECT_EQ(static_cast<string>(buf), string("123456789"));
}

TEST_F (BuffersTest, CharIterator)
{
    auto buf = genBuf("123", "456", "789");
    vector<u_char> test_vec;
    for (auto iter : buf) {
        test_vec.push_back(iter);
    }
    vector<u_char> expect_vec = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    EXPECT_EQ(test_vec, expect_vec);

    auto it = buf.begin() + 2;
    EXPECT_EQ(*(it), '3');
    it += 2;
    EXPECT_EQ(*(it), '5');
    ++it;
    EXPECT_EQ(*(it), '6');
}

TEST_F (BuffersTest, empty_CharIterator)
{
    cptestPrepareToDie();
    auto it = Buffer::CharIterator();
    EXPECT_DEATH(*(it), "Buffer::CharIterator is not pointing to a real value");
}

TEST_F(BuffersTest, serialization)
{
    stringstream stream;
    {
        cereal::JSONOutputArchive ar(stream);
        ar(genBuf("aaa", "bb", "c"));
    }
    Buffer buf;
    {
        cereal::JSONInputArchive ar(stream);
        ar(buf);
    }
    EXPECT_EQ(buf, Buffer("aaabbc"));
}

TEST_F (BuffersTest, find_first_of_ch)
{
    Buffer b1("boundary=Heeelllo;extrastuff;");
    uint index = b1.findFirstOf('=').unpack();
    EXPECT_TRUE(b1[index] == '=');
    EXPECT_TRUE(index == 8);
    Buffer b2("boundary");
    EXPECT_TRUE(b2 == b1.getSubBuffer(0, index));
}

TEST_F (BuffersTest, find_first_of_buf)
{
    Buffer b1("boundary=Heeelllo;extrastuff;");
    Buffer find("=Heeel");
    uint index = b1.findFirstOf(find).unpack();
    EXPECT_TRUE(b1[index] == '=');
    EXPECT_TRUE(index == 8);
    Buffer b2("boundary");
    EXPECT_TRUE(b2 == b1.getSubBuffer(0, index));
}

TEST_F (BuffersTest, find_last_of)
{
    Buffer b1("boundary=Heeelllo;extrastuff;");
    auto index = b1.findLastOf('u');
    EXPECT_TRUE(index.ok());
    EXPECT_TRUE(b1[index.unpack()] == 'u');
    EXPECT_TRUE(index.unpack() == 25);
    Buffer b2("boundary=Heeelllo;extrast");
    EXPECT_TRUE(b2 == b1.getSubBuffer(0, index.unpack()));
}

TEST_F (BuffersTest, find_first_not_of)
{
    Buffer b1("    boundary  ");
    auto index = b1.findFirstNotOf(' ');
    EXPECT_TRUE(index.ok());
    EXPECT_TRUE(b1[index.unpack()] == 'b');
    EXPECT_TRUE(index.unpack() == 4);
    Buffer b2("    ");
    EXPECT_TRUE(b2 == b1.getSubBuffer(0, index.unpack()));
}

TEST_F (BuffersTest, find_last_not_of)
{
    Buffer b1("    boundary  ");
    auto index = b1.findLastNotOf(' ');
    EXPECT_TRUE(index.ok());
    EXPECT_TRUE(b1[index.unpack()] == 'y');
    EXPECT_TRUE(index.unpack() == 11);
    Buffer b2("    boundar");
    EXPECT_TRUE(b2 == b1.getSubBuffer(0, index.unpack()));
}

class SegmentsTest: public Test
{
public:
    Buffer::Segment
    genSeg(const string &str, Buffer::MemoryType type = Buffer::MemoryType::OWNED)
    {
        Buffer::Segment seg(reinterpret_cast<const u_char *>(str.c_str()), str.length(), type);
        return seg;
    }

};

TEST_F(SegmentsTest, empty_segmnet)
{
    Buffer::Segment seg;
    EXPECT_EQ(seg.size(), 0u);
}

TEST_F (SegmentsTest, assign)
{
    Buffer::Segment seg1 = genSeg("123456789");
    Buffer::Segment seg2 = seg1;
    EXPECT_EQ(seg1.size(), seg2.size());
    EXPECT_EQ(bcmp(seg1.data(), seg2.data(), 9), 0);
    Buffer::Segment seg3;
    seg3 = seg2;
    EXPECT_EQ(seg3.size(), 9u);
    EXPECT_EQ(seg2.size(), 9u);
    EXPECT_EQ(seg2.data(), seg3.data());
    EXPECT_EQ(seg1.size(), seg3.size());
}

TEST_F (SegmentsTest, move)
{
    Buffer::Segment seg1 = genSeg("123456789");
    EXPECT_EQ(seg1.size(), 9u);
    Buffer::Segment seg2 = std::move(seg1);
    EXPECT_EQ(seg1.size(), 0u);
    EXPECT_EQ(seg2.size(), 9u);
    EXPECT_EQ(seg1.data(), nullptr);
    EXPECT_EQ(bcmp(seg2.data(), "123456789", 9), 0);
    Buffer::Segment seg3;
    seg3 = (std::move(seg2));
    EXPECT_EQ(seg2.size(), 0u);
    EXPECT_EQ(seg3.size(), 9u);
    EXPECT_EQ(seg2.data(), nullptr);
    EXPECT_EQ(bcmp(seg3.data(), "123456789", 9), 0);
}

TEST_F(SegmentsTest, data)
{
    Buffer::Segment seg1 = genSeg("123456789");
    Buffer::Segment seg2 = genSeg("123456789");
    vector<u_char> vec = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    Buffer::Segment seg3 = Buffer::Segment(std::move(vec));
    Buffer::Segment seg4 = Buffer::Segment(seg3);
    EXPECT_EQ(seg1.size(), 9u);
    EXPECT_EQ(seg3.size(), 9u);
    EXPECT_EQ(seg4.size(), 9u);
    EXPECT_EQ(bcmp(seg1.data(), "123456789", 9), 0);
    EXPECT_EQ(bcmp(seg1.data(), seg2.data(), 9), 0);
    EXPECT_EQ(bcmp(seg1.data(), seg3.data(), 9), 0);
    EXPECT_EQ(bcmp(seg4.data(), seg3.data(), 9), 0);
}

TEST_F(SegmentsTest, move_volatile)
{
    Buffer::Segment seg1;
    {
        Buffer::Segment seg2 = genSeg("123456789", Buffer::MemoryType::VOLATILE);
        seg1 = move(seg2);
    }
    EXPECT_EQ(bcmp(seg1.data(), "123456789", 9), 0);
}
