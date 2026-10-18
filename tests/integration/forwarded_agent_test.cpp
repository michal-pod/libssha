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

// Requests made by clients on the other side of a forwarded agent connection,
// OpenSSH ssh-agent allows all of them
namespace nglab::libssha::test::integration
{
    using ::testing::HasSubstr;

    TEST_F(AgentIntegration, ForwardedClientAddsAndRemovesKeys)
    {
        ASSERT_EQ(sshAddKey("rsa").exitCode, 0);

        auto add = ssh({"host_a"}, "ssh-add " + m_env->userKey("ed25519"));
        EXPECT_THAT(add.output(), HasSubstr("Identity added"));
        EXPECT_EQ(lineCount(sshAdd({"-l"}).out), 2u);

        auto remove = ssh({"host_a"}, "ssh-add -d " + m_env->userKey("ed25519") + ".pub");
        EXPECT_THAT(remove.output(), HasSubstr("Identity removed"));
        EXPECT_EQ(lineCount(sshAdd({"-l"}).out), 1u);
    }

    TEST_F(AgentIntegration, ForwardedClientRemovesAllKeys)
    {
        ASSERT_EQ(sshAddKey("rsa").exitCode, 0);
        ASSERT_EQ(sshAddKey("ed25519").exitCode, 0);

        EXPECT_THAT(ssh({"host_a"}, "ssh-add -D").output(), HasSubstr("All identities removed."));
        EXPECT_THAT(sshAdd({"-l"}).output(), HasSubstr(NoIdentities));
    }

    TEST_F(AgentIntegration, ForwardedClientLocksAgent)
    {
        ASSERT_EQ(sshAddKey("rsa").exitCode, 0);

        std::string command;
        for (const auto &[name, value] : askpass(LockPassphrase))
        {
            command += name + "=" + value + " ";
        }
        EXPECT_THAT(ssh({"host_a"}, command + "ssh-add -x").output(), HasSubstr("Agent locked."));
        EXPECT_THAT(sshAdd({"-l"}).output(), HasSubstr(NoIdentities));
        EXPECT_TRUE(unlockAgent());
    }

    // Destination constraints count from the origin, also for a key added on a forwarding host
    TEST_F(AgentIntegration, KeyAddedThroughForwardingIsConstrainedFromOrigin)
    {
        ASSERT_EQ(sshAddKey("rsa", {"host_a"}).exitCode, 0);
        auto add = ssh({"host_a"}, "ssh-add -H " + m_env->knownHosts() + " -h host_b " + m_env->userKey("ecdsa256"));
        ASSERT_THAT(add.output(), HasSubstr("Identity added"));

        EXPECT_THAT(ssh({"host_b"}, "echo connected_to_host_b").output(), HasSubstr("connected_to_host_b"));
        EXPECT_THAT(ssh({"host_a", "host_b"}, "echo connected_to_host_b").output(), HasSubstr(PermissionDenied));
    }
}
