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
#include <libssha/messages/message.h>
#include <libssha/messages/sign-request.h>
#include <libssha/utils/serializer.h>
#include <botan/secmem.h>

using namespace nglab::libssha;

// Protocol numbers from RFC 9987, sections 8.1, 8.2 and 8.3
static_assert(SSH_AGENT_FAILURE == 5);
static_assert(SSH_AGENT_SUCCESS == 6);
static_assert(SSH_AGENTC_REQUEST_IDENTITIES == 11);
static_assert(SSH_AGENT_IDENTITIES_ANSWER == 12);
static_assert(SSH_AGENTC_SIGN_REQUEST == 13);
static_assert(SSH_AGENT_SIGN_RESPONSE == 14);
static_assert(SSH_AGENTC_ADD_IDENTITY == 17);
static_assert(SSH_AGENTC_REMOVE_IDENTITY == 18);
static_assert(SSH_AGENTC_REMOVE_ALL_IDENTITIES == 19);
static_assert(SSH_AGENTC_ADD_SMARTCARD_KEY == 20);
static_assert(SSH_AGENTC_REMOVE_SMARTCARD_KEY == 21);
static_assert(SSH_AGENTC_LOCK == 22);
static_assert(SSH_AGENTC_UNLOCK == 23);
static_assert(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED == 25);
static_assert(SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED == 26);
static_assert(SSH_AGENTC_EXTENSION == 27);
static_assert(SSH_AGENT_EXTENSION_FAILURE == 28);
static_assert(SSH_AGENT_EXTENSION_RESPONSE == 29);
static_assert(SSH_AGENT_CONSTRAIN_LIFETIME == 1);
static_assert(SSH_AGENT_CONSTRAIN_CONFIRM == 2);
static_assert(SSH_AGENT_CONSTRAIN_EXTENSION == 255);
static_assert(SSH_AGENT_RSA_SHA2_256 == 2);
static_assert(SSH_AGENT_RSA_SHA2_512 == 4);

TEST(MessageTest, ConstructFromSerializedData) {
    Serializer s;
    s.writeBE32(1); // length of type field
    s.writeByte(SSH_AGENTC_SIGN_REQUEST);
    auto data = s.data();

    Message msg(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    EXPECT_EQ(msg.type(), SSH_AGENTC_SIGN_REQUEST);
    EXPECT_EQ(msg.typeName(), "SSH_AGENTC_SIGN_REQUEST");
}

TEST(MessageTest, ConstructFromString) {
    Serializer s;
    s.writeBE32(1);
    s.writeByte(SSH_AGENTC_REMOVE_ALL_IDENTITIES);
    auto data = s.data();
    std::string str(reinterpret_cast<const char*>(data.data()), data.size());

    Message msg(str);
    EXPECT_EQ(msg.type(), SSH_AGENTC_REMOVE_ALL_IDENTITIES);
    EXPECT_EQ(msg.typeName(), "SSH_AGENTC_REMOVE_ALL_IDENTITIES");
}

TEST(MessageTest, ConstructFromType) {
    Message msg(SSH_AGENTC_LOCK);
    EXPECT_EQ(msg.type(), SSH_AGENTC_LOCK);
    EXPECT_EQ(msg.typeName(), "SSH_AGENTC_LOCK");
}

TEST(MessageTest, Serialize) {
    Message msg(SSH_AGENTC_UNLOCK);
    auto serialized = msg.serialize();
    ASSERT_EQ(serialized.size(), 5);
    EXPECT_EQ(serialized[4], SSH_AGENTC_UNLOCK);
}

TEST(MessageTest, TypeNameUnknown) {
    Message msg(0xFF);
    EXPECT_EQ(msg.typeName(), "UNKNOWN");
}

TEST(MessageTest, AllTypeNameMappings) {
    struct {
        MessageType type;
        const char* name;
    } known_types[] = {
        {SSH_AGENTC_REQUEST_IDENTITIES, "SSH_AGENTC_REQUEST_IDENTITIES"},
        {SSH_AGENTC_SIGN_REQUEST, "SSH_AGENTC_SIGN_REQUEST"},
        {SSH_AGENTC_ADD_IDENTITY, "SSH_AGENTC_ADD_IDENTITY"},
        {SSH_AGENTC_REMOVE_IDENTITY, "SSH_AGENTC_REMOVE_IDENTITY"},
        {SSH_AGENTC_REMOVE_ALL_IDENTITIES, "SSH_AGENTC_REMOVE_ALL_IDENTITIES"},
        {SSH_AGENTC_LOCK, "SSH_AGENTC_LOCK"},
        {SSH_AGENTC_UNLOCK, "SSH_AGENTC_UNLOCK"},
        {SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, "SSH_AGENTC_ADD_ID_CONSTRAINED"},
        {SSH_AGENTC_EXTENSION, "SSH_AGENTC_EXTENSION"},
        {SSH_AGENT_FAILURE, "SSH_AGENT_FAILURE"},
        {SSH_AGENT_SUCCESS, "SSH_AGENT_SUCCESS"},
        {SSH_AGENT_IDENTITIES_ANSWER, "SSH_AGENT_IDENTITIES_ANSWER"},
        {SSH_AGENT_SIGN_RESPONSE, "SSH_AGENT_SIGN_RESPONSE"},
        {SSH_AGENTC_ADD_SMARTCARD_KEY, "SSH_AGENTC_ADD_SMARTCARD_KEY"},
        {SSH_AGENTC_REMOVE_SMARTCARD_KEY, "SSH_AGENTC_REMOVE_SMARTCARD_KEY"},
        {SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED, "SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED"},
        {SSH_AGENT_EXTENSION_FAILURE, "SSH_AGENT_EXTENSION_FAILURE"},
        {SSH_AGENT_EXTENSION_RESPONSE, "SSH_AGENT_EXTENSION_RESPONSE"}
    };

    for (const auto& entry : known_types) {
        Message msg(static_cast<uint8_t>(entry.type));
        EXPECT_EQ(msg.typeName(), entry.name) << "Type: " << int(entry.type);
    }
}
