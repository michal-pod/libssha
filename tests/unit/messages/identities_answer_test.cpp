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
#include <libssha/messages/identities-answer.h>
#include <libssha/messages/message.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/secure_vector.h>
#include <vector>
#include <string>
#include <stdexcept>

using namespace nglab::libssha;

TEST(IdentitiesAnswerMessage, DefaultConstructor) {
    IdentitiesAnswerMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENT_IDENTITIES_ANSWER);
    EXPECT_TRUE(msg.identities().empty());
}

TEST(IdentitiesAnswerMessage, AddIdentityAndAccess) {
    IdentitiesAnswerMessage msg;
    std::vector<uint8_t> blob = {1,2,3,4};
    std::string comment = "test";
    msg.addIdentity(blob, comment);

    ASSERT_EQ(msg.identities().size(), 1);
    EXPECT_EQ(msg.identities()[0].blob(), blob);
    EXPECT_EQ(msg.identities()[0].comment(), comment);
}

TEST(IdentitiesAnswerMessage, SerializeDeserializeRoundTrip) {
    IdentitiesAnswerMessage msg;
    std::vector<uint8_t> blob1 = {10,20,30};
    std::string comment1 = "first";
    std::vector<uint8_t> blob2 = {40,50,60};
    std::string comment2 = "second";
    msg.addIdentity(blob1, comment1);
    msg.addIdentity(blob2, comment2);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    IdentitiesAnswerMessage msg2(base_msg);

    ASSERT_EQ(msg2.identities().size(), 2);
    EXPECT_EQ(msg2.identities()[0].blob(), blob1);
    EXPECT_EQ(msg2.identities()[0].comment(), comment1);
    EXPECT_EQ(msg2.identities()[1].blob(), blob2);
    EXPECT_EQ(msg2.identities()[1].comment(), comment2);
}

TEST(IdentitiesAnswerMessage, ConstructorFromInvalidTypeThrows) {
    Message wrong_type_msg(static_cast<uint8_t>(SSH_AGENTC_SIGN_REQUEST));
    EXPECT_THROW(IdentitiesAnswerMessage msg(wrong_type_msg), std::runtime_error);
}

TEST(IdentitiesAnswerMessage, DeserializeNotEnoughDataThrows) {
    Serializer s;
    s.writeBE32(0); // length
    s.writeByte(SSH_AGENT_IDENTITIES_ANSWER);
    s.writeBE32(5); // count, but no identities
    s.finalize();

    auto message_data = s.data();

    Message base_msg(message_data.data(), message_data.size());
    EXPECT_THROW(IdentitiesAnswerMessage msg(base_msg), std::out_of_range);
}
