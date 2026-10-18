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
    const std::string NoIdentities = "The agent has no identities.";
    const std::string LockPassphrase = "testpassword";

    // Each test gets its own directory and its own agent, nothing it does to the
    // agent can leak into the next test. With LIBSSHA_TEST_AGENT=openssh the agent
    // is OpenSSH ssh-agent, to check the expectations against the reference.
    class AgentIntegration : public ::testing::Test
    {
    protected:
        void SetUp() override;
        void TearDown() override;

        static bool referenceAgent();

        ProcessResult sshAdd(std::vector<std::string> args, const Environment &env = {});
        ProcessResult sshAddKey(const std::string &key, const std::vector<std::string> &constraints = {});
        ProcessResult sshKeygen(const std::vector<std::string> &args, const std::string &stdinFile = "/dev/null");

        // Runs the command on the last host, connecting through the earlier ones
        // with the agent forwarded at each hop, options apply to the first hop
        ProcessResult ssh(const std::vector<std::string> &hops, const std::string &command,
                          const std::vector<std::string> &options = {});

        bool lockAgent();
        bool unlockAgent();

        // Environment for ssh-add -x/-X, the passphrase comes from SSH_ASKPASS
        Environment askpass(const std::string &passphrase);
        // A new ed25519 key in the test directory, returns its path
        std::string generateKey(const std::string &name);

        static size_t lineCount(const std::string &text);
        static std::string userName();

        std::unique_ptr<TestEnvironment> m_env;
        std::unique_ptr<BackgroundProcess> m_agent;
    };
}
