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
    // Same as OpenSSH: a locked agent lists no keys instead of refusing the request
    TEST_F(AgentIntegration, LockedAgentListsNoKeys)
    {
        for (const auto &key : KeyNames)
        {
            ASSERT_EQ(sshAddKey(key).exitCode, 0) << key;
        }
        ASSERT_TRUE(lockAgent());

        EXPECT_THAT(sshAdd({"-l"}).output(), ::testing::HasSubstr("The agent has no identities."));

        ASSERT_TRUE(unlockAgent());
        auto list = sshAdd({"-l"});
        EXPECT_EQ(list.exitCode, 0);
        EXPECT_EQ(lineCount(list.out), KeyNames.size()) << list.out;
        EXPECT_EQ(sshAdd({"-D"}).exitCode, 0);
    }

    // RFC 9987, section 5.7
    TEST_F(AgentIntegration, UnlockingUnlockedAgentFails)
    {
        EXPECT_FALSE(unlockAgent());
    }
}
