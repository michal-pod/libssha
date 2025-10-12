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
#include <gtest/gtest.h>
#include <libssha/messages/sign-request.h>
#include <libssha/messages/message.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/secure_vector.h>
#include <vector>
#include <stdexcept>

using namespace nglab::libssha;

TEST(SignRequestMessage, DefaultConstructor) {
    SignRequestMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_SIGN_REQUEST);
    EXPECT_EQ(msg.flags(), 0u);
    EXPECT_TRUE(msg.keyBlob().empty());
    EXPECT_TRUE(msg.data().empty());
}

TEST(SignRequestMessage, SettersAndGetters) {
    SignRequestMessage msg;
    std::vector<uint8_t> key_blob = {1, 2, 3};
    vector<uint8_t> data = {4, 5, 6};
    uint32_t flags = 99;

    msg.setKeyBlob(key_blob);
    msg.setData(data);
    msg.setFlags(flags);

    EXPECT_EQ(msg.keyBlob(), key_blob);
    EXPECT_EQ(msg.data(), data);
    EXPECT_EQ(msg.flags(), flags);
}

TEST(SignRequestMessage, SerializeDeserializeRoundTrip) {
    SignRequestMessage msg;
    std::vector<uint8_t> key_blob = {10, 20, 30};
    vector<uint8_t> data = {40, 50, 60};
    uint32_t flags = 1234;
    msg.setKeyBlob(key_blob);
    msg.setData(data);
    msg.setFlags(flags);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    SignRequestMessage msg2(base_msg);

    EXPECT_EQ(msg2.keyBlob(), key_blob);
    EXPECT_EQ(msg2.data(), data);
    EXPECT_EQ(msg2.flags(), flags);
}

TEST(SignRequestMessage, ConstructorFromValidMessage) {
    std::vector<uint8_t> key_blob = {7, 8, 9};
    vector<uint8_t> data = {1, 2, 3};
    uint32_t flags = 55;

    Serializer s;
    s.writeBE32(0);
    s.writeByte(SSH_AGENTC_SIGN_REQUEST);
    s.writeBlob(key_blob);
    s.writeBlob(data);
    s.writeBE32(flags);
    s.finalize();

    auto message_blob = s.data();

    Message base_msg(message_blob.data(), message_blob.size());
    SignRequestMessage msg(base_msg);

    EXPECT_EQ(msg.keyBlob(), key_blob);
    EXPECT_EQ(msg.data(), data);
    EXPECT_EQ(msg.flags(), flags);
}

TEST(SignRequestMessage, ConstructorFromInvalidTypeThrows) {
    Serializer s;
    s.writeByte(0xFF); // Wrong type
    s.writeString("abc");
    s.writeString("def");
    s.writeBE32(0);
    s.finalize();

    Message base_msg(s.data().data(), s.data().size());
    EXPECT_THROW(SignRequestMessage msg(base_msg), std::runtime_error);
}

TEST(SignRequestMessage, EmptyBlobsAndZeroFlags) {
    SignRequestMessage msg;
    msg.setKeyBlob({});
    msg.setData(vector<uint8_t>());
    msg.setFlags(0);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    SignRequestMessage msg2(base_msg);

    EXPECT_TRUE(msg2.keyBlob().empty());
    EXPECT_TRUE(msg2.data().empty());
    EXPECT_EQ(msg2.flags(), 0u);
}
