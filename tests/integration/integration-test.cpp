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
#include "integration-config.h"
#include <botan/base64.h>
#include <pwd.h>
#include <unistd.h>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace nglab::libssha::test::integration
{
    void AgentIntegration::SetUp()
    {
        m_env = std::make_unique<TestEnvironment>();
        std::vector<std::string> agent{TEST_AGENT_PATH, m_env->agentSocket()};
        if (referenceAgent())
        {
            agent = {SSH_AGENT_PATH, "-D", "-a", m_env->agentSocket()};
        }
        // Both agents ask SSH_ASKPASS to confirm keys added with ssh-add -c
        const std::string confirm = m_env->path("confirm");
        std::ofstream(confirm) << "#!/bin/sh\ntest -e '" << m_env->path("confirm-allow") << "'\n";
        std::filesystem::permissions(confirm, std::filesystem::perms::owner_all);
        Environment agentEnv{{"LIBSSHA_LOG_COLORS", "0"}, {"SSH_ASKPASS", confirm}, {"SSH_ASKPASS_REQUIRE", "force"}};
        m_agent = std::make_unique<BackgroundProcess>(agent, agentEnv, m_env->agentLog());
        ASSERT_TRUE(AgentClient::waitForAgent(m_env->agentSocket(), std::chrono::seconds(5)))
            << agent[0] << " did not start, see " << m_env->agentLog();
    }

    bool AgentIntegration::referenceAgent()
    {
        const char *agent = std::getenv("LIBSSHA_TEST_AGENT");
        return agent != nullptr && std::string(agent) == "openssh";
    }

    void AgentIntegration::TearDown()
    {
        m_agent.reset();
        if (HasFailure() && m_env)
        {
            std::ifstream log(m_env->agentLog());
            std::cerr << "--- " << m_env->agentLog() << "\n" << log.rdbuf() << "---\n";
        }
        m_env.reset();
    }

    ProcessResult AgentIntegration::sshAdd(std::vector<std::string> args, const Environment &env)
    {
        // ssh-add looks up the host keys of -h in ~/.ssh/known_hosts by default
        if (std::find(args.begin(), args.end(), "-h") != args.end())
        {
            args.insert(args.begin(), {"-H", m_env->knownHosts()});
        }
        args.insert(args.begin(), SSH_ADD_PATH);
        Environment merged = env;
        merged["SSH_AUTH_SOCK"] = m_env->agentSocket();
        return runProcess(args, merged);
    }

    ProcessResult AgentIntegration::sshAddKey(const std::string &key, const std::vector<std::string> &constraints)
    {
        std::vector<std::string> args;
        for (const auto &constraint : constraints)
        {
            args.push_back("-h");
            args.push_back(constraint);
        }
        args.push_back(m_env->userKey(key));
        return sshAdd(args);
    }

    ProcessResult AgentIntegration::sshKeygen(const std::vector<std::string> &args, const std::string &stdinFile)
    {
        std::vector<std::string> full{SSH_KEYGEN_PATH};
        full.insert(full.end(), args.begin(), args.end());
        return runProcess(full, {{"SSH_AUTH_SOCK", m_env->agentSocket()}}, stdinFile);
    }

    ProcessResult AgentIntegration::ssh(const std::vector<std::string> &hops, const std::string &command,
                                        const std::vector<std::string> &options)
    {
        // The remote shell splits the words again, so the nested ssh needs no quoting
        // as long as the paths and the command have no spaces to protect
        std::vector<std::string> args;
        for (const auto &host : hops)
        {
            args.insert(args.end(), {SSH_PATH, "-F", m_env->sshConfig()});
            if (args.size() == 3)
            {
                args.insert(args.end(), options.begin(), options.end());
            }
            args.push_back(host);
        }
        std::istringstream words(command);
        for (std::string word; words >> word;)
        {
            args.push_back(word);
        }
        return runProcess(args, {{"SSH_AUTH_SOCK", m_env->agentSocket()}});
    }

    bool AgentIntegration::lockAgent()
    {
        return AgentClient(m_env->agentSocket()).lock(LockPassphrase);
    }

    bool AgentIntegration::unlockAgent()
    {
        return AgentClient(m_env->agentSocket()).unlock(LockPassphrase);
    }

    void AgentIntegration::allowConfirmations(bool allow)
    {
        if (allow)
        {
            std::ofstream(m_env->path("confirm-allow"));
        }
        else
        {
            std::filesystem::remove(m_env->path("confirm-allow"));
        }
    }

    Environment AgentIntegration::askpass(const std::string &passphrase)
    {
        // One script per passphrase, the passphrase has no characters the shell would expand
        const std::string script = m_env->path("askpass-" + passphrase);
        std::ofstream(script) << "#!/bin/sh\necho '" << passphrase << "'\n";
        std::filesystem::permissions(script, std::filesystem::perms::owner_all);
        return {{"SSH_ASKPASS", script}, {"SSH_ASKPASS_REQUIRE", "force"}};
    }

    std::string AgentIntegration::generateKey(const std::string &name, const std::string &comment)
    {
        const std::string path = m_env->path(name);
        auto result = sshKeygen({"-q", "-t", "ed25519", "-N", "", "-C", comment.empty() ? name : comment, "-f", path});
        if (result.exitCode != 0)
        {
            ADD_FAILURE() << "ssh-keygen " << name << ": " << result.output();
        }
        return path;
    }

    size_t AgentIntegration::lineCount(const std::string &text)
    {
        return std::count(text.begin(), text.end(), '\n');
    }

    std::string AgentIntegration::userName()
    {
        const passwd *pw = getpwuid(getuid());
        return pw != nullptr ? pw->pw_name : "";
    }

    std::vector<uint8_t> AgentIntegration::publicKeyBlob(const std::string &key)
    {
        std::ifstream pub(m_env->userKey(key) + ".pub");
        std::string type;
        std::string base64;
        pub >> type >> base64;
        auto blob = Botan::base64_decode(base64);
        return std::vector<uint8_t>(blob.begin(), blob.end());
    }
}
