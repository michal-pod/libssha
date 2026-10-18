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
}
