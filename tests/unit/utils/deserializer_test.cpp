/*
 * This file is part of libssha - C++ SSH Agent Library
 * Copyright (C) 2025 Michał Podsiadlik <michal@nglab.net>
 *
 * libssha is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libssha is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libssha. If not, see <http://www.gnu.org/licenses/>.
 */
#include <libssha/utils/deserializer.h>
#include <gtest/gtest.h>
#include <libssha/utils/secure_vector.h>
#include <stdexcept>
#include <string>
#include <vector>

using namespace nglab::libssha;

TEST(DeserializerTest, ReadBE32)
{
    unsigned char data[] = {0x12, 0x34, 0x56, 0x78};
    Deserializer d(data, sizeof(data));
    EXPECT_EQ(d.readBE32(), 0x12345678u);
}

TEST(DeserializerTest, ReadByte)
{
    unsigned char data[] = {0xAB, 0xCD};
    Deserializer d(data, sizeof(data));
    EXPECT_EQ(d.readByte(), 0xAB);
    EXPECT_EQ(d.readByte(), 0xCD);
    EXPECT_THROW(d.readByte(), std::out_of_range);
}

TEST(DeserializerTest, ReadBlob)
{
    // Length = 3, data = "abc"
    unsigned char data[] = {0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'};
    Deserializer d(data, sizeof(data));
    EXPECT_EQ(d.readString(), "abc");
    EXPECT_THROW(d.readBlob(), std::out_of_range);
}

TEST(DeserializerTest, ReadSecureBlob)
{
    // Length = 2, data = {0xDE, 0xAD}
    unsigned char data[] = {0x00, 0x00, 0x00, 0x02, 0xDE, 0xAD};
    Deserializer d(data, sizeof(data));
    secure_vector<uint8_t> blob = d.readBlobSecure();
    ASSERT_EQ(blob.size(), 2);
    EXPECT_EQ(blob[0], 0xDE);
    EXPECT_EQ(blob[1], 0xAD);
    EXPECT_THROW(d.readBlobSecure(), std::out_of_range);
}

TEST(DeserializerTest, StringConstructor)
{
    std::string s = "\x01\x02\x03\x04";
    Deserializer d(s);
    EXPECT_EQ(d.readBE32(), 0x01020304u);
}

TEST(DeserializerTest, OutOfRangeBE32)
{
    unsigned char data[] = {0x00, 0x00, 0x00};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.readBE32(), std::out_of_range);
}

TEST(DeserializerTest, OutOfRangeBlob)
{
    unsigned char data[] = {0x00, 0x00, 0x00, 0x05, 'a', 'b', 'c'};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.readBlob(), std::out_of_range);
}

TEST(DeserializerTest, OutOfRangeSecureBlob)
{
    unsigned char data[] = {0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.readBlobSecure(), std::out_of_range);
}

TEST(DeserializerTest, DiscardBlob)
{
    unsigned char data[] = {0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x01};
    Deserializer d(data, sizeof(data));
    d.discardBlob();
    EXPECT_EQ(d.readByte(), 0x01);
}

TEST(DeserializerTest, DiscardBlobOutOfRange)
{
    unsigned char data[] = {0x00, 0x00, 0x00, 0x05, 0xAA, 0xBB};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.discardBlob(), std::out_of_range);
}

TEST(DeserializerTest, SliceValid)
{
    unsigned char data[] = {0x01, 0x02, 0x03, 0x04};
    Deserializer d(data, sizeof(data));
    secure_vector<uint8_t> s = d.sliceSecure(1, 3);
    ASSERT_EQ(s.size(), 2);
    EXPECT_EQ(s[0], 0x02);
    EXPECT_EQ(s[1], 0x03);
}

TEST(DeserializerTest, SliceInvalid)
{
    unsigned char data[] = {0x01, 0x02, 0x03};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.slice(2, 1), std::out_of_range);
    EXPECT_THROW(d.slice(0, 4), std::out_of_range);
}

TEST(DeserializerTest, MultipleReads)
{
    // Read a sequence of blobs and bytes
    unsigned char data[] = {
        0x00, 0x00, 0x00, 0x01, 0xAA, // blob "0xAA"
        0x00, 0x00, 0x00, 0x02, 0xBB, 0xCC, // blob "0xBB 0xCC"
        0xDD // byte
    };
    Deserializer d(data, sizeof(data));
    EXPECT_EQ(d.readBlob(), std::vector<uint8_t>({0xAA}));
    EXPECT_EQ(d.readBlob(), std::vector<uint8_t>({0xBB, 0xCC}));
    EXPECT_EQ(d.readByte(), 0xDD);
    EXPECT_THROW(d.readByte(), std::out_of_range);
}

TEST(DeserializerTest, ReadSecureBlobWithZeroLength)
{
    unsigned char data[] = {0x00, 0x00, 0x00, 0x00};
    Deserializer d(data, sizeof(data));
    secure_vector<uint8_t> blob = d.readBlobSecure();
    EXPECT_TRUE(blob.empty());
}

TEST(DeserializerTest, ReadBlobWithZeroLength)
{
    unsigned char data[] = {0x00, 0x00, 0x00, 0x00};
    Deserializer d(data, sizeof(data));
    std::string blob = d.readString();
    EXPECT_TRUE(blob.empty());
}

TEST(DeserializerTest, ReadMPIntVectorEmpty) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x00};
    Deserializer d(data, sizeof(data));
    std::vector<uint8_t> mpint = d.readMPInt();
    EXPECT_TRUE(mpint.empty());
}

TEST(DeserializerTest, ReadMPIntSecureVectorEmpty) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x00};
    Deserializer d(data, sizeof(data));
    secure_vector<uint8_t> mpint = d.readMPIntSecure();
    EXPECT_TRUE(mpint.empty());
}

TEST(DeserializerTest, ReadMPIntVectorHighBit) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x01};
    Deserializer d(data, sizeof(data));
    std::vector<uint8_t> mpint = d.readMPInt();
    ASSERT_EQ(mpint.size(), 2);    
    EXPECT_EQ(mpint[0], 0x80);
    EXPECT_EQ(mpint[1], 0x01);
}

TEST(DeserializerTest, ReadMPIntSecureVectorHighBit) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x01};
    Deserializer d(data, sizeof(data));
    secure_vector<uint8_t> mpint = d.readMPIntSecure();
    ASSERT_EQ(mpint.size(), 2);    
    EXPECT_EQ(mpint[0], 0x80);
    EXPECT_EQ(mpint[1], 0x01);
}

TEST(DeserializerTest, ReadMPIntVectorNormal) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x02, 0x01, 0x02};
    Deserializer d(data, sizeof(data));
    std::vector<uint8_t> mpint = d.readMPInt();
    ASSERT_EQ(mpint.size(), 2);
    EXPECT_EQ(mpint[0], 0x01);
    EXPECT_EQ(mpint[1], 0x02);
}

TEST(DeserializerTest, ReadMPIntSecureVectorNormal) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x02, 0x01, 0x02};
    Deserializer d(data, sizeof(data));
    secure_vector<uint8_t> mpint = d.readMPIntSecure();
    ASSERT_EQ(mpint.size(), 2);
    EXPECT_EQ(mpint[0], 0x01);
    EXPECT_EQ(mpint[1], 0x02);
}

TEST(DeserializerTest, ReadMPIntVectorOutOfRange) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x05, 0x01, 0x02};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.readMPInt(), std::out_of_range);
}

TEST(DeserializerTest, ReadMPIntSecureVectorOutOfRange) {
    unsigned char data[] = {0x00, 0x00, 0x00, 0x05, 0x01, 0x02};
    Deserializer d(data, sizeof(data));
    EXPECT_THROW(d.readMPIntSecure(), std::out_of_range);
}

