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

#include <libssha/utils/secure_vector.h>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace nglab::libssha::test::integration
{
    // Talks to the agent directly, for requests that ssh-add cannot shape and for
    // locking in tests that are about the agent rather than about ssh-add
    class AgentClient
    {
    public:
        explicit AgentClient(const std::string &socketPath);
        ~AgentClient();

        AgentClient(const AgentClient &) = delete;
        AgentClient &operator=(const AgentClient &) = delete;

        // True when the agent answered SSH_AGENT_SUCCESS
        bool lock(const std::string &passphrase);
        bool unlock(const std::string &passphrase);

        // Raw access for framing tests, sendRaw writes exactly the given bytes
        void sendRaw(const std::vector<uint8_t> &data);
        // One response without its length, the first byte is the message type
        std::vector<uint8_t> readResponse();

        // Waits until the agent accepts connections
        static bool waitForAgent(const std::string &socketPath, std::chrono::milliseconds timeout);

    private:
        uint8_t request(const secure_vector<uint8_t> &message);

        int m_fd = -1;
    };
}
