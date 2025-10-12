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
#include <libssha/messages/lock-message.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <vector>
#include <string>

using namespace nglab::libssha;

TEST(LockMessageBaseTest, DefaultConstructorSetsType)
{
    LockMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_LOCK);
    EXPECT_TRUE(msg.password().empty());
}

TEST(LockMessageBaseTest, SetAndGetPassword)
{
    LockMessage msg;
    secure_vector<uint8_t> pass = {1,2,3,4};
    msg.setPassword(pass);
    EXPECT_EQ(msg.password(), pass);
}

TEST(LockMessageBaseTest, SerializeAndDeserializeRoundTrip)
{
    LockMessage msg;
    secure_vector<uint8_t> pass = {0xAA, 0xBB, 0xCC};
    msg.setPassword(pass);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    LockMessage msg2(base_msg);
    EXPECT_EQ(msg2.password(), pass);
}

TEST(LockMessageBaseTest, ConstructFromMessageWorks)
{
    LockMessage msg;
    secure_vector<uint8_t> pass = {0x11, 0x22};
    msg.setPassword(pass);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    LockMessage parsed(base_msg);
    EXPECT_EQ(parsed.type(), SSH_AGENTC_LOCK);
    EXPECT_EQ(parsed.password(), pass);
}

TEST(LockMessageBaseTest, ConstructFromMessageWrongTypeThrows)
{
    Serializer s;
    s.writeByte(0xFF); // Wrong type
    s.writeSecureBlob({1,2,3});
    s.finalize();
    Message wrong_msg(s.dataSecure().data(), s.dataSecure().size());
    EXPECT_THROW(LockMessage parsed(wrong_msg), std::runtime_error);
}

TEST(LockMessageBaseTest, ConstructFromMessageNoDataThrows)
{
    // Message with valid SSH agent header (length + type), but no password blob
    Message empty_msg({0x00, 0x00, 0x00, 0x01, SSH_AGENTC_LOCK});
    EXPECT_THROW(LockMessage parsed(empty_msg), std::runtime_error);
}

TEST(UnlockMessageTest, DefaultConstructorSetsType)
{
    UnlockMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_UNLOCK);
    EXPECT_TRUE(msg.password().empty());
}

TEST(UnlockMessageTest, SetAndGetPassword)
{
    UnlockMessage msg;
    secure_vector<uint8_t> pass = {5,6,7,8};
    msg.setPassword(pass);
    EXPECT_EQ(msg.password(), pass);
}

TEST(UnlockMessageTest, SerializeAndDeserializeRoundTrip)
{
    UnlockMessage msg;
    secure_vector<uint8_t> pass = {0xDE, 0xAD, 0xBE};
    msg.setPassword(pass);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    UnlockMessage msg2(base_msg);
    EXPECT_EQ(msg2.password(), pass);
}

TEST(UnlockMessageTest, ConstructFromMessageWorks)
{
    UnlockMessage msg;
    secure_vector<uint8_t> pass = {0x33, 0x44};
    msg.setPassword(pass);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    UnlockMessage parsed(base_msg);
    EXPECT_EQ(parsed.type(), SSH_AGENTC_UNLOCK);
    EXPECT_EQ(parsed.password(), pass);
}

TEST(UnlockMessageTest, ConstructFromMessageWrongTypeThrows)
{
    Serializer s;
    s.writeByte(0xFE); // Wrong type
    s.writeSecureBlob({9,8,7});
    s.finalize();
    Message wrong_msg(s.dataSecure().data(), s.dataSecure().size());
    EXPECT_THROW(UnlockMessage parsed(wrong_msg), std::runtime_error);
}

TEST(UnlockMessageTest, ConstructFromMessageNoDataThrows)
{
    // Message with valid SSH agent header (length + type), but no password blob
    Message empty_msg({0x00, 0x00, 0x00, 0x01, SSH_AGENTC_UNLOCK});
    EXPECT_THROW(UnlockMessage parsed(empty_msg), std::runtime_error);
}
