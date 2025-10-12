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
#include <libssha/utils/serializer.h>
#include <gtest/gtest.h>
#include <libssha/utils/secure_vector.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <limits>

using namespace nglab::libssha;

TEST(SerializerTest, WriteBE32AppendAndOverwrite) {
    Serializer s;
    s.writeBE32(0x12345678);
    ASSERT_EQ(s.data().size(), 4);
    EXPECT_EQ(s.data()[0], 0x12);
    EXPECT_EQ(s.data()[1], 0x34);
    EXPECT_EQ(s.data()[2], 0x56);
    EXPECT_EQ(s.data()[3], 0x78);

    // Overwrite at position 0
    s.writeBE32(0xAABBCCDD, 0);
    EXPECT_EQ(s.data()[0], 0xAA);
    EXPECT_EQ(s.data()[1], 0xBB);
    EXPECT_EQ(s.data()[2], 0xCC);
    EXPECT_EQ(s.data()[3], 0xDD);

    // Out of range overwrite
    EXPECT_THROW(s.writeBE32(0xDEADBEEF, 100), std::out_of_range);
}

TEST(SerializerTest, WriteByteAppendAndOverwrite) {
    Serializer s;
    s.writeByte(0x42);
    ASSERT_EQ(s.data().size(), 1);
    EXPECT_EQ(s.data()[0], 0x42);

    s.writeByte(0x99);
    ASSERT_EQ(s.data().size(), 2);
    EXPECT_EQ(s.data()[1], 0x99);

    // Overwrite at position 0
    s.writeByte(0x77, 0);
    EXPECT_EQ(s.data()[0], 0x77);

    // Out of range overwrite
    EXPECT_THROW(s.writeByte(0xFF, 10), std::out_of_range);
}

TEST(SerializerTest, WriteBlobWorksAndEnforcesSizeLimit) {
    Serializer s;
    std::vector<uint8_t> blob = {'h', 'e', 'l', 'l', 'o'};
    s.writeBlob(blob);
    ASSERT_EQ(s.data().size(), 4 + blob.size());
    EXPECT_EQ(s.data()[4], 'h');
    EXPECT_EQ(s.data()[8], 'o');

    // Exceed max size
    Serializer s2;
    std::vector<uint8_t> big_blob;
    big_blob.resize(256 * 1024 + 1, 0xFF);
    EXPECT_THROW(s2.writeBlob(big_blob), std::length_error);
}

TEST(SerializerTest, WriteSecureBlobWorksAndEnforcesSizeLimit) {
    Serializer s;
    secure_vector<uint8_t> blob = {1,2,3,4,5};
    s.writeSecureBlob(blob);
    ASSERT_EQ(s.data().size(), 4 + blob.size());
    EXPECT_EQ(s.data()[4], 1);
    EXPECT_EQ(s.data()[8], 5);

    // Exceed max size
    Serializer s2;
    secure_vector<uint8_t> big_blob(256 * 1024 + 1, 0xAA);
    EXPECT_THROW(s2.writeSecureBlob(big_blob), std::length_error);
}

TEST(SerializerTest, FinalizeSetsLengthAtStart) {
    Serializer s;
    s.writeBE32(0x0); // Placeholder for length
    s.writeByte(0x11);
    s.writeByte(0x22);
    s.finalize();
    // Length should be 2 (bytes after first 4)
    EXPECT_EQ(s.data()[0], 0x00);
    EXPECT_EQ(s.data()[1], 0x00);
    EXPECT_EQ(s.data()[2], 0x00);
    EXPECT_EQ(s.data()[3], 0x02);

    // Not enough data to finalize
    Serializer s2;
    EXPECT_THROW(s2.finalize(), std::runtime_error);
}

TEST(SerializerTest, DataReturnsCorrectVector) {
    Serializer s;
    s.writeByte(0xAB);
    auto d = s.data();
    ASSERT_EQ(d.size(), 1);
    EXPECT_EQ(d[0], 0xAB);
}

TEST(SerializerTest, MaxSerializedSizeBoundary) {
    Serializer s;
    std::string blob(256 * 1024 - 4, 'a');
    s.writeString(blob);
    EXPECT_EQ(s.data().size(), 256 * 1024);

    // Adding one more byte should throw
    EXPECT_THROW(s.writeByte(0x01), std::length_error);
}

TEST(SerializerTest, MultipleOperationsSequence) {
    Serializer s;
    s.writeBE32(0x01020304);
    s.writeByte(0xAA);
    s.writeString("xyz");
    s.writeSecureBlob(secure_vector<uint8_t>{0xBB, 0xCC});
    s.finalize();

    auto d = s.data();
    // Check length at start
    EXPECT_EQ(d[0], 0x00);
    EXPECT_EQ(d[1], 0x00);
    EXPECT_EQ(d[2], 0x00);
    EXPECT_EQ(d[3], d.size() - 4);
}

TEST(SerializerTest, WriteRawString) {
    Serializer s;
    s.writeRaw(std::string("abc"));
    auto d = s.data();
    ASSERT_EQ(d.size(), 3);
    EXPECT_EQ(d[0], 'a');
    EXPECT_EQ(d[1], 'b');
    EXPECT_EQ(d[2], 'c');
}

TEST(SerializerTest, WriteRawSecureVector) {
    Serializer s;
    secure_vector<uint8_t> raw = {0x11, 0x22, 0x33};
    s.writeRaw(raw);
    auto d = s.data();
    ASSERT_EQ(d.size(), 3);
    EXPECT_EQ(d[0], 0x11);
    EXPECT_EQ(d[1], 0x22);
    EXPECT_EQ(d[2], 0x33);
}

TEST(SerializerTest, WriteRawStringSizeLimit) {
    Serializer s;
    s.writeString("test");
    
    std::string big(256 * 1024, 'x');
    EXPECT_THROW(s.writeRaw(big), std::length_error);
}

TEST(SerializerTest, WriteRawSecureVectorSizeLimit) {
    Serializer s;
    s.writeString("test");
    secure_vector<uint8_t> big(256 * 1024, 0x42);
    EXPECT_THROW(s.writeRaw(big), std::length_error);
}

TEST(SerializerTest, WriteMPIntEmptyVector) {
    Serializer s;
    std::vector<uint8_t> empty_vec;
    s.writeMPInt(empty_vec);
    auto d = s.data();
    ASSERT_EQ(d.size(), 4);
    EXPECT_EQ(d[0], 0x00);
    EXPECT_EQ(d[1], 0x00);
    EXPECT_EQ(d[2], 0x00);
    EXPECT_EQ(d[3], 0x00);
}

TEST(SerializerTest, WriteMPIntEmptySecureVector) {
    Serializer s;
    secure_vector<uint8_t> empty_vec;
    s.writeMPInt(empty_vec);
    auto d = s.data();
    ASSERT_EQ(d.size(), 4);
    EXPECT_EQ(d[0], 0x00);
    EXPECT_EQ(d[1], 0x00);
    EXPECT_EQ(d[2], 0x00);
    EXPECT_EQ(d[3], 0x00);
}

TEST(SerializerTest, WriteMPIntHighBitVector) {
    Serializer s;
    std::vector<uint8_t> mpint = {0x80, 0x01};
    s.writeMPInt(mpint);
    auto d = s.data();
    // Should prepend a 0x00 byte
    ASSERT_EQ(d.size(), 4 + 3);
    EXPECT_EQ(d[4], 0x00);
    EXPECT_EQ(d[5], 0x80);
    EXPECT_EQ(d[6], 0x01);
}

TEST(SerializerTest, WriteMPIntHighBitSecureVector) {
    Serializer s;
    secure_vector<uint8_t> mpint = {0x80, 0x01};
    s.writeMPInt(mpint);
    auto d = s.data();
    // Should prepend a 0x00 byte
    ASSERT_EQ(d.size(), 4 + 3);
    EXPECT_EQ(d[4], 0x00);
    EXPECT_EQ(d[5], 0x80);
    EXPECT_EQ(d[6], 0x01);
}

TEST(SerializerTest, WriteMPIntNormalVector) {
    Serializer s;
    std::vector<uint8_t> mpint = {0x01, 0x02};
    s.writeMPInt(mpint);
    auto d = s.data();
    ASSERT_EQ(d.size(), 4 + 2);
    EXPECT_EQ(d[4], 0x01);
    EXPECT_EQ(d[5], 0x02);
}

TEST(SerializerTest, WriteMPIntNormalSecureVector) {
    Serializer s;
    secure_vector<uint8_t> mpint = {0x01, 0x02};
    s.writeMPInt(mpint);
    auto d = s.data();
    ASSERT_EQ(d.size(), 4 + 2);
    EXPECT_EQ(d[4], 0x01);
    EXPECT_EQ(d[5], 0x02);
}

TEST(SerializerTest, WriteMPIntSizeLimit) {
    Serializer s;
    std::vector<uint8_t> big_mpint(256 * 1024, 0x01);
    EXPECT_THROW(s.writeMPInt(big_mpint), std::length_error);

    Serializer s2;
    secure_vector<uint8_t> big_mpint2(256 * 1024, 0x01);
    EXPECT_THROW(s2.writeMPInt(big_mpint2), std::length_error);
}

TEST(SerializerTest, WriteRawEmptyStringAndVector) {
    Serializer s;
    s.writeRaw(std::string());
    s.writeRaw(secure_vector<uint8_t>());
    EXPECT_EQ(s.data().size(), 0);
}

TEST(SerializerTest, WriteStringEmpty) {
    Serializer s;
    s.writeString("");
    auto d = s.data();
    ASSERT_EQ(d.size(), 4);
    EXPECT_EQ(d[0], 0x00);
    EXPECT_EQ(d[1], 0x00);
    EXPECT_EQ(d[2], 0x00);
    EXPECT_EQ(d[3], 0x00);
}

TEST(SerializerTest, SerializerSizeMethod) {
    Serializer s;
    EXPECT_EQ(s.size(), 0);
    s.writeByte(0x01);
    EXPECT_EQ(s.size(), 1);
    s.writeString("abc");
    EXPECT_EQ(s.size(), 1 + 4 + 3);
}
