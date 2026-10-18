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
#include <mutex>
#include <thread>

// The agent process and its socket handling, with real clients
namespace nglab::libssha::test::integration
{
    namespace detail
    {
        // RFC 9987, section 5.3: SSH_AGENTC_REQUEST_IDENTITIES has no payload
        const std::vector<uint8_t> RequestIdentities{0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES};
    }

    TEST_F(AgentIntegration, RequestSplitIntoSingleBytes)
    {
        AgentClient client(m_env->agentSocket());
        for (uint8_t byte : detail::RequestIdentities)
        {
            client.sendRaw({byte});
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_IDENTITIES_ANSWER);
    }

    TEST_F(AgentIntegration, TwoRequestsInOneWrite)
    {
        AgentClient client(m_env->agentSocket());
        auto twoRequests = detail::RequestIdentities;
        twoRequests.insert(twoRequests.end(), detail::RequestIdentities.begin(), detail::RequestIdentities.end());
        client.sendRaw(twoRequests);
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_IDENTITIES_ANSWER);
        EXPECT_EQ(client.readResponse()[0], SSH_AGENT_IDENTITIES_ANSWER);
    }

    TEST_F(AgentIntegration, ConcurrentClients)
    {
        ASSERT_EQ(sshAddKey("ed25519").exitCode, 0);

        std::mutex mutex;
        std::vector<std::string> failures;
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; ++i)
        {
            threads.emplace_back(
                [&]
                {
                    for (int round = 0; round < 3; ++round)
                    {
                        auto list = sshAdd({"-l"});
                        auto login = ssh({"host_a"}, "echo connected_to_host_a");
                        std::lock_guard<std::mutex> lock(mutex);
                        if (list.exitCode != 0 || lineCount(list.out) != 1)
                            failures.push_back("ssh-add -l: " + list.output());
                        if (login.output().find("connected_to_host_a") == std::string::npos)
                            failures.push_back("ssh: " + login.output());
                    }
                });
        }
        for (auto &thread : threads)
        {
            thread.join();
        }
        EXPECT_TRUE(failures.empty()) << failures.size() << " failures, first: " << failures.front();
    }

    // The identities answer is large and the keys come from one ssh-add call
    TEST_F(AgentIntegration, ManyKeysAreListed)
    {
        const size_t count = 40;
        std::vector<std::string> keys;
        for (size_t i = 0; i < count; ++i)
        {
            keys.push_back(generateKey("many_" + std::to_string(i)));
        }
        ASSERT_EQ(sshAdd(keys).exitCode, 0);

        auto list = sshAdd({"-L"});
        EXPECT_EQ(list.exitCode, 0);
        EXPECT_EQ(lineCount(list.out), count);
    }
}
