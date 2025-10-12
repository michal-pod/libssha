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
#include <libssha/messages/sign-response.h>
#include <libssha/messages/message.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/secure_vector.h>
#include <vector>
#include <stdexcept>

using namespace nglab::libssha;

TEST(SignResponseMessage, DefaultConstructor) {
    SignResponseMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENT_SIGN_RESPONSE);
    EXPECT_TRUE(msg.signature().empty());
}

TEST(SignResponseMessage, SettersAndGetters) {
    SignResponseMessage msg;
    std::vector<uint8_t> data = {1, 2, 3, 4};
    msg.setSignature(data);
    EXPECT_EQ(msg.signature(), data);
}

TEST(SignResponseMessage, SerializeDeserializeRoundTrip) {
    SignResponseMessage msg;
    std::vector<uint8_t> data = {10, 20, 30};
    msg.setSignature(data);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    SignResponseMessage msg2(base_msg);

    EXPECT_EQ(msg2.signature(), data);
}

TEST(SignResponseMessage, ConstructorFromValidMessage) {
    std::vector<uint8_t> data = {5, 6, 7};
    Serializer s;
    s.writeBE32(0); // Placeholder for length
    s.writeByte(SSH_AGENT_SIGN_RESPONSE);
    s.writeBlob(data);
    s.finalize();

    auto data_blob = s.data();

    Message base_msg(data_blob.data(), data_blob.size());
    SignResponseMessage msg(base_msg);

    EXPECT_EQ(msg.signature(), data);
}

TEST(SignResponseMessage, ConstructorFromInvalidTypeThrows) {
    Serializer s;
    s.writeByte(0xFF); // Wrong type
    s.writeString("abc");
    s.finalize();

    auto data_blob = s.data();

    Message base_msg(data_blob.data(), data_blob.size());
    EXPECT_THROW(SignResponseMessage msg(base_msg), std::runtime_error);
}


