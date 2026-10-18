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
#pragma once

#include "process.h"
#include "test-environment.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace nglab::libssha::test::integration
{
    const std::string PermissionDenied = "Permission denied (publickey).";

    // Each test gets its own directory and its own test-agent, nothing it does
    // to the agent can leak into the next test
    class AgentIntegration : public ::testing::Test
    {
    protected:
        void SetUp() override;
        void TearDown() override;

        ProcessResult sshAdd(std::vector<std::string> args);
        ProcessResult sshAddKey(const std::string &key, const std::vector<std::string> &constraints = {});

        // Runs the command on the last host, connecting through the earlier ones
        // with the agent forwarded at each hop
        ProcessResult ssh(const std::vector<std::string> &hops, const std::string &command);

        bool lockAgent();
        bool unlockAgent();

        static size_t lineCount(const std::string &text);
        static std::string userName();

        std::unique_ptr<TestEnvironment> m_env;
        std::unique_ptr<BackgroundProcess> m_agent;
    };
}
