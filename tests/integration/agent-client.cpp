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
#include "agent-client.h"
#include <libssha/messages/lock-message.h>
#include <libssha/messages/message.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

namespace nglab::libssha::test::integration
{
    namespace detail
    {
        int connectAgent(const std::string &socketPath)
        {
            int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0)
            {
                return -1;
            }
            sockaddr_un addr{};
            addr.sun_family = AF_UNIX;
            std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
            if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
            {
                close(fd);
                return -1;
            }
            return fd;
        }

        void readExactly(int fd, uint8_t *data, size_t length)
        {
            while (length > 0)
            {
                ssize_t n = read(fd, data, length);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n <= 0)
                {
                    throw std::runtime_error("Agent closed the connection");
                }
                data += n;
                length -= n;
            }
        }
    }

    AgentClient::AgentClient(const std::string &socketPath)
        : m_fd(detail::connectAgent(socketPath))
    {
        if (m_fd < 0)
        {
            throw std::runtime_error("Cannot connect to the agent at " + socketPath);
        }
    }

    AgentClient::~AgentClient()
    {
        close(m_fd);
    }

    bool AgentClient::lock(const std::string &passphrase)
    {
        LockMessage msg;
        msg.setPassword(secure_vector<uint8_t>(passphrase.begin(), passphrase.end()));
        return request(msg.serialize()) == SSH_AGENT_SUCCESS;
    }

    bool AgentClient::unlock(const std::string &passphrase)
    {
        UnlockMessage msg;
        msg.setPassword(secure_vector<uint8_t>(passphrase.begin(), passphrase.end()));
        return request(msg.serialize()) == SSH_AGENT_SUCCESS;
    }

    bool AgentClient::waitForAgent(const std::string &socketPath, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            int fd = detail::connectAgent(socketPath);
            if (fd >= 0)
            {
                close(fd);
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    }

    uint8_t AgentClient::request(const secure_vector<uint8_t> &message)
    {
        if (write(m_fd, message.data(), message.size()) != static_cast<ssize_t>(message.size()))
        {
            throw std::runtime_error("Cannot send the request to the agent");
        }

        // RFC 9987, section 3: uint32 length followed by the message
        uint8_t header[4];
        detail::readExactly(m_fd, header, sizeof(header));
        const uint32_t length = (uint32_t(header[0]) << 24) | (uint32_t(header[1]) << 16) |
                                (uint32_t(header[2]) << 8) | uint32_t(header[3]);
        if (length == 0 || length > 256 * 1024)
        {
            throw std::runtime_error("Invalid response length from the agent");
        }
        std::vector<uint8_t> body(length);
        detail::readExactly(m_fd, body.data(), body.size());
        return body[0];
    }
}
