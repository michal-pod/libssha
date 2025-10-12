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
#include <libssha/messages/userauth-request.h>
#include <libssha/utils/serializer.h>
#include <vector>
#include <string>

using namespace nglab::libssha;

namespace {

std::vector<uint8_t> makeValidUserAuthRequest(
    const std::vector<uint8_t>& session_id,
    const std::string& username,
    const std::string& key_type,
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& server_host_key)
{
    Serializer s;
    s.writeBlob(session_id);
    s.writeByte(50); // SSH_MSG_USERAUTH_REQUEST
    s.writeString(username);
    s.writeString("ssh-connection");
    s.writeString("publickey-hostbound-v00@openssh.com");
    s.writeByte(1); // has signature
    s.writeString(key_type);
    s.writeBlob(public_key);
    s.writeBlob(server_host_key);
    auto blob = s.data();
    return std::vector<uint8_t>(blob.begin(), blob.end());
}

TEST(UserAuthRequestMessageTest, ParsesValidMessage)
{
    std::vector<uint8_t> session_id = {0x01, 0x02, 0x03};
    std::string username = "alice";
    std::string key_type = "ssh-ed25519";
    std::vector<uint8_t> public_key = {0x11, 0x22};
    std::vector<uint8_t> server_host_key = {0x33, 0x44};

    auto data = makeValidUserAuthRequest(session_id, username, key_type, public_key, server_host_key);

    UserAuthRequestMessage msg(data);

    EXPECT_EQ(msg.sessionId(), session_id);
    EXPECT_EQ(msg.username(), username);
    EXPECT_EQ(msg.keyType(), key_type);
    EXPECT_EQ(msg.publicKey(), public_key);
    EXPECT_EQ(msg.serverHostKey(), server_host_key);
}

TEST(UserAuthRequestMessageTest, ThrowsOnEmptySessionId)
{
    std::vector<uint8_t> session_id; // empty
    std::string username = "bob";
    std::string key_type = "ssh-ed25519";
    std::vector<uint8_t> public_key = {0x11};
    std::vector<uint8_t> server_host_key = {0x22};

    auto data = makeValidUserAuthRequest(session_id, username, key_type, public_key, server_host_key);

    EXPECT_THROW(UserAuthRequestMessage msg(data), std::runtime_error);
}

TEST(UserAuthRequestMessageTest, ThrowsOnWrongMsgType)
{
    std::vector<uint8_t> session_id = {0x01};
    std::string username = "bob";
    std::string key_type = "ssh-ed25519";
    std::vector<uint8_t> public_key = {0x11};
    std::vector<uint8_t> server_host_key = {0x22};

    auto data = makeValidUserAuthRequest(session_id, username, key_type, public_key, server_host_key);
    data[session_id.size()+4] = 0xFF; // corrupt the msg_type byte

    EXPECT_THROW(UserAuthRequestMessage msg(data), std::runtime_error);
}

TEST(UserAuthRequestMessageTest, ThrowsOnUnsupportedServiceOrMethodOrSignature)
{
    std::vector<uint8_t> session_id = {0x01};
    std::string username = "bob";
    std::string key_type = "ssh-ed25519";
    std::vector<uint8_t> public_key = {0x11};
    std::vector<uint8_t> server_host_key = {0x22};

    // Wrong service name
    {
        Serializer s;
        s.writeBlob(session_id);
        s.writeByte(50);
        s.writeString(username);
        s.writeString("not-ssh-connection");
        s.writeString("publickey-hostbound-v00@openssh.com");
        s.writeByte(1);
        s.writeString(key_type);
        s.writeBlob(public_key);
        s.writeBlob(server_host_key);
        auto blob = s.data();
        EXPECT_THROW(UserAuthRequestMessage msg(std::vector<uint8_t>(blob.begin(), blob.end())), std::runtime_error);
    }

    // Wrong method name
    {
        Serializer s;
        s.writeBlob(session_id);
        s.writeByte(50);
        s.writeString(username);
        s.writeString("ssh-connection");
        s.writeString("not-publickey-hostbound");
        s.writeByte(1);
        s.writeString(key_type);
        s.writeBlob(public_key);
        s.writeBlob(server_host_key);
        auto blob = s.data();
        EXPECT_THROW(UserAuthRequestMessage msg(std::vector<uint8_t>(blob.begin(), blob.end())), std::runtime_error);
    }

    // No signature
    {
        Serializer s;
        s.writeBlob(session_id);
        s.writeByte(50);
        s.writeString(username);
        s.writeString("ssh-connection");
        s.writeString("publickey-hostbound-v00@openssh.com");
        s.writeByte(0); // has_signature = false
        s.writeString(key_type);
        s.writeBlob(public_key);
        s.writeBlob(server_host_key);
        auto blob = s.data();
        EXPECT_THROW(UserAuthRequestMessage msg(std::vector<uint8_t>(blob.begin(), blob.end())), std::runtime_error);
    }
}

} // namespace
