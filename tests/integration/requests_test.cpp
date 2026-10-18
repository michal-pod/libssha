/*
 * This file is part of libssha - C++ SSH Agent Library
 * Copyright (C) 2026 Michał Podsiadlik <michal@nglab.net>
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
#include "integration-test.h"
#include "agent-client.h"
#include <libssha/messages/message.h>
#include <libssha/utils/serializer.h>

// Requests the agent has to refuse, made by ssh-add or directly
namespace nglab::libssha::test::integration
{
    using ::testing::HasSubstr;

    namespace detail
    {
        std::vector<uint8_t> framed(Serializer &s)
        {
            s.finalize();
            const auto &data = s.data();
            return std::vector<uint8_t>(data.begin(), data.end());
        }

        // RFC 9987, section 5.6
        std::vector<uint8_t> signRequest(const std::vector<uint8_t> &keyBlob)
        {
            Serializer s;
            s.writeBE32(0);
            s.writeByte(SSH_AGENTC_SIGN_REQUEST);
            s.writeBlob(keyBlob);
            s.writeString("data to sign");
            s.writeBE32(0);
            return framed(s);
        }

        // RFC 9987, section 5.8
        std::vector<uint8_t> extensionRequest(const std::string &name)
        {
            Serializer s;
            s.writeBE32(0);
            s.writeByte(SSH_AGENTC_EXTENSION);
            s.writeString(name);
            return framed(s);
        }
    }

    // RFC 9987, section 5.4
    TEST_F(AgentIntegration, RemovingMissingKeyFails)
    {
        ASSERT_EQ(sshAddKey("ed25519").exitCode, 0);
        EXPECT_NE(sshAdd({"-d", m_env->userKey("rsa") + ".pub"}).exitCode, 0);
        EXPECT_EQ(lineCount(sshAdd({"-l"}).out), 1u);
    }

    // RFC 9987, section 5.6
    TEST_F(AgentIntegration, SigningWithMissingKeyFails)
    {
        ASSERT_EQ(sshAddKey("ed25519").exitCode, 0);
        EXPECT_NE(sshAdd({"-T", m_env->userKey("rsa") + ".pub"}).exitCode, 0);

        AgentClient client(m_env->agentSocket());
        client.sendRaw(detail::signRequest(publicKeyBlob("rsa")));
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_FAILURE);
    }

    // RFC 9987, section 5.7: a locked agent signs nothing, even for a client that knows the key
    TEST_F(AgentIntegration, LockedAgentRefusesSigning)
    {
        ASSERT_EQ(sshAddKey("ed25519").exitCode, 0);
        ASSERT_TRUE(lockAgent());

        AgentClient client(m_env->agentSocket());
        client.sendRaw(detail::signRequest(publicKeyBlob("ed25519")));
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_FAILURE);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr(PermissionDenied));

        ASSERT_TRUE(unlockAgent());
        client.sendRaw(detail::signRequest(publicKeyBlob("ed25519")));
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_SIGN_RESPONSE);
    }

    // RFC 9987, section 5.7
    TEST_F(AgentIntegration, LockingLockedAgentFails)
    {
        ASSERT_TRUE(lockAgent());
        EXPECT_FALSE(lockAgent());
        EXPECT_TRUE(unlockAgent());
    }

    // RFC 9987, section 5.8: an extension the agent does not know gets the plain FAILURE
    TEST_F(AgentIntegration, UnknownExtensionGetsFailure)
    {
        AgentClient client(m_env->agentSocket());
        client.sendRaw(detail::extensionRequest("unknown-extension@example.com"));
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_FAILURE);
    }

    // RFC 9987, section 5.8.1: the extension name followed by the supported names
    TEST_F(AgentIntegration, QueryListsSessionBind)
    {
        if (referenceAgent())
        {
            GTEST_SKIP() << "OpenSSH ssh-agent does not implement query";
        }
        AgentClient client(m_env->agentSocket());
        client.sendRaw(detail::extensionRequest("query"));
        auto response = client.readResponse();
        ASSERT_EQ(response[0], SSH_AGENT_EXTENSION_RESPONSE);
        const std::string names(response.begin() + 1, response.end());
        EXPECT_THAT(names, HasSubstr("session-bind@openssh.com"));
    }

    // RFC 9987, section 5.2.6: an agent without token support refuses PKCS#11 providers
    TEST_F(AgentIntegration, SmartcardProviderIsRefused)
    {
        auto add = sshAdd({"-s", m_env->path("missing-pkcs11.so")}, askpass("1234"));
        EXPECT_NE(add.exitCode, 0) << add.output();
        auto remove = sshAdd({"-e", m_env->path("missing-pkcs11.so")});
        EXPECT_NE(remove.exitCode, 0) << remove.output();
        EXPECT_THAT(sshAdd({"-l"}).output(), HasSubstr(NoIdentities));
    }
}
