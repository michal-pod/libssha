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
#include <thread>

namespace nglab::libssha::test::integration
{
    using ::testing::HasSubstr;

    TEST_F(AgentIntegration, ConstrainedKeyWorksOnlyForAllowedHost)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr("connected_to_host_a"));
        EXPECT_THAT(ssh({"host_b"}, "echo connected_to_host_b").output(), HasSubstr(PermissionDenied));
    }

    TEST_F(AgentIntegration, ForwardedAgentFollowsHopConstraints)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_c", "host_c>host_a"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_c", "host_a"}, "echo connected_to_host_a_via_forwarded_agent").output(),
                    HasSubstr("connected_to_host_a_via_forwarded_agent"));
        EXPECT_THAT(ssh({"host_c", "host_b"}, "echo connected_to_host_b_via_forwarded_agent").output(),
                    HasSubstr(PermissionDenied));
    }

    TEST_F(AgentIntegration, UserConstraintAllowsMatchingUser)
    {
        ASSERT_EQ(sshAddKey("ed25519", {userName() + "@host_a"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr("connected_to_host_a"));
    }

    TEST_F(AgentIntegration, UserConstraintRefusesOtherUser)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"invaliduser@host_a"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr(PermissionDenied));
    }

    TEST_F(AgentIntegration, TwoHopsThroughAllowedPath)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a", "host_a>host_b", "host_b>host_c"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a", "host_b", "host_c"}, "echo connected_to_host_c_via_2_hops").output(),
                    HasSubstr("connected_to_host_c_via_2_hops"));
    }

    TEST_F(AgentIntegration, ForwardedAgentListsOnlyPermittedKeys)
    {
        // An unconstrained key is visible everywhere
        ASSERT_EQ(sshAddKey("rsa").exitCode, 0);
        ASSERT_EQ(sshAddKey("ed25519", {"host_a", "host_a>host_b"}).exitCode, 0);
        ASSERT_EQ(sshAddKey("ecdsa256", {"host_a", "host_a>host_b"}).exitCode, 0);

        auto onHostA = ssh({"host_a"}, "ssh-add -l");
        EXPECT_EQ(lineCount(onHostA.out), 3u) << onHostA.output();
        auto onHostB = ssh({"host_b"}, "ssh-add -l");
        EXPECT_EQ(lineCount(onHostB.out), 1u) << onHostB.output();
    }

    TEST_F(AgentIntegration, CycleBackToFirstHostIsRefused)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a", "host_a>host_b"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a", "host_b", "host_a"}, "echo connected_to_host_a_via_cycle").output(),
                    HasSubstr(PermissionDenied));
    }

    // RFC 9987, section 5.2.7.2: each use of a key added with ssh-add -c is confirmed
    TEST_F(AgentIntegration, ConfirmedUseSigns)
    {
        allowConfirmations(true);
        ASSERT_EQ(sshAdd({"-c", m_env->userKey("ed25519")}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr("connected_to_host_a"));
    }

    // RFC 9987, sections 5.2.7.2 and 5.6
    TEST_F(AgentIntegration, DeniedUseIsRefused)
    {
        allowConfirmations(false);
        ASSERT_EQ(sshAdd({"-c", m_env->userKey("ed25519")}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr(PermissionDenied));
    }

    // All constraints in one request, in the order ssh-add writes them
    TEST_F(AgentIntegration, CombinedConstraints)
    {
        allowConfirmations(true);
        ASSERT_EQ(sshAdd({"-c", "-t", "60", "-h", "host_a", m_env->userKey("ed25519")}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr("connected_to_host_a"));
        EXPECT_THAT(ssh({"host_b"}, "echo connected_to_host_b").output(), HasSubstr(PermissionDenied));
    }

    // RFC 9987, section 5.2: adding a key again replaces its constraints
    TEST_F(AgentIntegration, ReAddingKeyReplacesDestinationConstraint)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_b"}, "echo connected_to_host_b").output(), HasSubstr(PermissionDenied));

        ASSERT_EQ(sshAddKey("ed25519").exitCode, 0);
        EXPECT_EQ(lineCount(sshAdd({"-l"}).out), 1u);
        EXPECT_THAT(ssh({"host_b"}, "echo connected_to_host_b").output(), HasSubstr("connected_to_host_b"));
    }

    TEST_F(AgentIntegration, ReAddingKeyReplacesLifetime)
    {
        ASSERT_EQ(sshAdd({"-t", "60", m_env->userKey("ed25519")}).exitCode, 0);
        ASSERT_EQ(sshAdd({"-t", "1", m_env->userKey("ed25519")}).exitCode, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        EXPECT_THAT(sshAdd({"-l"}).output(), HasSubstr(NoIdentities));
    }

    TEST_F(AgentIntegration, UserConstraintOnForwardedHop)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a", "host_a>" + userName() + "@host_b"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a", "host_b"}, "echo connected_to_host_b").output(), HasSubstr("connected_to_host_b"));
    }

    TEST_F(AgentIntegration, OtherUserOnForwardedHopIsRefused)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a", "host_a>invaliduser@host_b"}).exitCode, 0);
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), HasSubstr("connected_to_host_a"));
        EXPECT_THAT(ssh({"host_a", "host_b"}, "echo connected_to_host_b").output(), HasSubstr(PermissionDenied));
    }
}
