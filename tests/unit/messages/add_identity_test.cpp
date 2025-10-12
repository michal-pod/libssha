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
#include <libssha/messages/add-identity.h>
#include <libssha/messages/message.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/secure_vector.h>
#include <vector>
#include <stdexcept>

using namespace nglab::libssha;

TEST(AddIdentityMessage, DefaultConstructor)
{
    AddIdentityMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_ADD_IDENTITY);
    EXPECT_EQ(msg.keyType(), "");
    EXPECT_EQ(msg.keyComment(), "");
    EXPECT_TRUE(msg.keyBlob().empty());
    EXPECT_FALSE(msg.confirmRequired());
    EXPECT_EQ(msg.lifetime(), 0u);
}

TEST(AddIdentityMessage, SettersAndGetters)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("test comment");
    secure_vector<uint8_t> blob = {1, 2, 3, 4};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(true);
    msg.setLifetime(123);

    EXPECT_EQ(msg.keyType(), "ssh-ed25519");
    EXPECT_EQ(msg.keyComment(), "test comment");
    EXPECT_EQ(msg.keyBlob(), blob);
    EXPECT_TRUE(msg.confirmRequired());
    EXPECT_EQ(msg.lifetime(), 123u);
}

TEST(AddIdentityMessage, SerializeDeserializeRoundTripEd25519)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("comment");
    secure_vector<uint8_t> blob = {0x00, 0x00, 0x00, 0x02,
                                          0xAA, 0xBB,
                                          0x00, 0x00, 0x00, 0x04,
                                          0xCC, 0xDD, 0xEE, 0xFF};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(true);
    msg.setLifetime(42);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    AddIdentityMessage msg2(base_msg);

    EXPECT_EQ(msg2.keyType(), msg.keyType());
    EXPECT_EQ(msg2.keyComment(), msg.keyComment());
    EXPECT_EQ(msg2.keyBlob(), msg.keyBlob());
    EXPECT_EQ(msg2.confirmRequired(), msg.confirmRequired());
    EXPECT_EQ(msg2.lifetime(), msg.lifetime());
}

TEST(AddIdentityMessage, SerializeDeserializeRoundTripRSA)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-rsa");
    msg.setKeyComment("rsa comment");
    secure_vector<uint8_t> blob = {0x00, 0x00, 0x00, 0x03,
                                          0x11, 0x22, 0x33,
                                          0x00, 0x00, 0x00, 0x03,
                                          0x44, 0x55, 0x66,
                                          0x00, 0x00, 0x00, 0x03,
                                          0x77, 0x88, 0x99,
                                          0x00, 0x00, 0x00, 0x03,
                                          0xAA, 0xBB, 0xCC,
                                          0x00, 0x00, 0x00, 0x03,
                                          0xDD, 0xEE, 0xFF,
                                          0x00, 0x00, 0x00, 0x03,
                                          0x10, 0x20, 0x30};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(false);
    msg.setLifetime(0);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    AddIdentityMessage msg2(base_msg);

    EXPECT_EQ(msg2.keyType(), msg.keyType());
    EXPECT_EQ(msg2.keyComment(), msg.keyComment());
    EXPECT_EQ(msg2.keyBlob(), msg.keyBlob());
    EXPECT_EQ(msg2.confirmRequired(), msg.confirmRequired());
    EXPECT_EQ(msg2.lifetime(), msg.lifetime());
}

TEST(AddIdentityMessage, ConstructorFromInvalidTypeThrows)
{
    std::string invalid_message_payload = {0x00, 0x00, 0x00, 0x01, 0x42}; // Length + invalid type
    Message wrong_type_msg(reinterpret_cast<const uint8_t *>(invalid_message_payload.data()), invalid_message_payload.size());
    // Set type manually if needed, or use a valid buffer with wrong type byte
    EXPECT_THROW(AddIdentityMessage msg(wrong_type_msg), std::runtime_error);
}

TEST(AddIdentityMessage, UnsupportedKeyTypeThrows)
{
    Serializer s;
    s.writeBE32(0); // Placeholder for length
    s.writeByte(SSH_AGENTC_ADD_IDENTITY);
    s.writeString("unsupported-key-type");
    s.writeBlob({0x10, 0x20, 0x30});
    s.writeBlob({0x40, 0x50, 0x60});
    s.writeString("comment");
    s.finalize();

    Message base_msg(s.data().data(), s.data().size());
    EXPECT_THROW(AddIdentityMessage msg(base_msg), std::runtime_error);
}

TEST(AddIdentityMessage, ContructorWithConstrains)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("test comment");
    secure_vector<uint8_t> blob = {1, 2, 3, 4};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(true);
    msg.setLifetime(123);

    EXPECT_EQ(msg.type(), SSH_AGENTC_ADD_IDENTITY_CONSTRAINED);
    EXPECT_EQ(msg.keyType(), "ssh-ed25519");
    EXPECT_EQ(msg.keyComment(), "test comment");
    EXPECT_EQ(msg.keyBlob(), blob);
    EXPECT_TRUE(msg.confirmRequired());
    EXPECT_EQ(msg.lifetime(), 123u);
}