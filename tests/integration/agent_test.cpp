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
    TEST_F(AgentIntegration, NewAgentHasNoIdentities)
    {
        auto result = sshAdd({"-l"});
        EXPECT_THAT(result.output(), ::testing::HasSubstr(NoIdentities));
    }

    // The lifetime constraint removes the key after the given number of seconds
    TEST_F(AgentIntegration, KeyExpiresAfterLifetime)
    {
        ASSERT_EQ(sshAdd({"-t", "1", m_env->userKey("ed25519")}).exitCode, 0);
        EXPECT_EQ(lineCount(sshAdd({"-l"}).out), 1u);

        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        EXPECT_THAT(sshAdd({"-l"}).output(), ::testing::HasSubstr(NoIdentities));
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a").output(), ::testing::HasSubstr(PermissionDenied));
    }
}
