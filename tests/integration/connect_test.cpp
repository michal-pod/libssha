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
#include <tuple>

namespace nglab::libssha::test::integration
{
    // Key and the host to log in to
    class ConnectTest : public AgentIntegration, public ::testing::WithParamInterface<std::tuple<std::string, std::string>>
    {
    };

    TEST_P(ConnectTest, ConnectBeforeAndAfterLock)
    {
        const auto &[key, host] = GetParam();
        const std::string expected = "connected_to_" + host;

        ASSERT_EQ(sshAddKey(key).exitCode, 0);
        EXPECT_THAT(ssh({host}, "echo " + expected).output(), ::testing::HasSubstr(expected));

        ASSERT_TRUE(lockAgent());
        ASSERT_TRUE(unlockAgent());
        EXPECT_THAT(ssh({host}, "echo " + expected).output(), ::testing::HasSubstr(expected));

        EXPECT_EQ(sshAdd({"-d", m_env->userKey(key)}).exitCode, 0);
    }

    INSTANTIATE_TEST_SUITE_P(KeyTypes, ConnectTest,
                             ::testing::Values(std::make_tuple("rsa", "host_a"), std::make_tuple("rsa3072", "host_a"),
                                               std::make_tuple("rsa4096", "host_a"), std::make_tuple("ecdsa256", "host_b"),
                                               std::make_tuple("ecdsa384", "host_b"), std::make_tuple("ecdsa521", "host_b"),
                                               std::make_tuple("ed25519", "host_c")),
                             [](const auto &info) { return std::get<0>(info.param); });
}
