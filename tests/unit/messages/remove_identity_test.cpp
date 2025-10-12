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
#include <libssha/messages/remove-identity.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <vector>
#include <string>

using namespace nglab::libssha;

TEST(RemoveIdentityMessageTest, DefaultConstructorSetsType)
{
    RemoveIdentityMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_REMOVE_IDENTITY);
    EXPECT_TRUE(msg.keyBlob().empty());
}

TEST(RemoveIdentityMessageTest, SetAndGetKeyBlob)
{
    RemoveIdentityMessage msg;
    std::vector<uint8_t> blob = {1,2,3,4};
    msg.setKeyBlob(blob);
    EXPECT_EQ(msg.keyBlob(), blob);
}

TEST(RemoveIdentityMessageTest, SerializeAndDeserializeRoundTrip)
{
    RemoveIdentityMessage msg;
    std::vector<uint8_t> blob = {0xAA, 0xBB, 0xCC};
    msg.setKeyBlob(blob);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    // Simulate receiving the message
    RemoveIdentityMessage msg2(base_msg);

    EXPECT_EQ(msg2.keyBlob(), blob);
}

TEST(RemoveIdentityMessageTest, ConstructFromMessageWorks)
{
    RemoveIdentityMessage msg;
    std::vector<uint8_t> blob = {0x11, 0x22};
    msg.setKeyBlob(blob);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    RemoveIdentityMessage parsed(base_msg);
    EXPECT_EQ(parsed.type(), SSH_AGENTC_REMOVE_IDENTITY);
    EXPECT_EQ(parsed.keyBlob(), blob);
}

TEST(RemoveIdentityMessageTest, ConstructFromMessageWrongTypeThrows)
{
    Serializer s;
    s.writeByte(0xFF); // Wrong type
    s.writeBlob({1,2,3});
    s.finalize();
    Message wrong_msg(s.dataSecure().data(), s.dataSecure().size());
    EXPECT_THROW(RemoveIdentityMessage parsed(wrong_msg), std::runtime_error);
}

TEST(RemoveIdentityMessageTest, ConstructFromMessageNoDataThrows)
{
    Message empty_msg({0x00, 0x00, 0x00, 0x01, SSH_AGENTC_REMOVE_IDENTITY}); // Type byte but no blob
    EXPECT_THROW(RemoveIdentityMessage parsed(empty_msg), std::runtime_error);
}
