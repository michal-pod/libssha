/*
 * This file is part of libssha - C++ SSH Agent Library
 * Copyright (C) 2025 Michał Podsiadlik <michal@nglab.net>
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
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdio>
#include <list>
#include <unistd.h>
#include <libssha/messages/message.h>
#include <libssha/messages/add-identity.h>
#include <libssha/messages/identities-answer.h>
#include <libssha/messages/sign-request.h>
#include <libssha/messages/sign-response.h>
#include <libssha/messages/extension.h>
#include <libssha/messages/userauth-request.h>
#include <libssha/agent/session.h>
#include <libssha/key/key-manager.h>
#include <libssha/providers/botan/botan-lock-provider.h>
#include <csignal>

class TestSession : public nglab::libssha::Session
{
public:
    TestSession(int fd) : Session(), m_fd(fd), LogEnabler("test-session") {}

    bool confirmRequest(const nglab::libssha::KeyBase& key) override
    {
        // For testing, always confi
        const auto &mi = matchInfo();
        log.info("Auto-confirming request for testing from host {} to host {}", mi.from, mi.to);
        return true;
    }

    bool requiresConfirmation(nglab::libssha::KeyBasePtr key) const override
    {
        return false;
    }



    std::string client() const override
    {
        return "test-client";
    }

    bool processExtensionMessage(const nglab::libssha::ExtensionMessage &msg) override
    {
        // For testing, do not process any extensions
        log.debug("Received extension message: {}", msg.extensionName());
        return false;
    }

    bool send(nglab::libssha::secure_vector<uint8_t> &data) override
    {
        // For testing, just log the data size
        log.vdebug("Sending response of size {}", data.size());
        ssize_t sent = ::send(m_fd, data.data(), data.size(), 0);
        if (sent < 0)
        {
            log.error("Failed to send data");
            return false;
        }
        return true;
    }

    int fd() const { return m_fd; }

private:
    int m_fd;
};

static volatile sig_atomic_t g_running = 1;

static void stop_handler(int)
{
    g_running = 0;
}

int main(int argc, char **argv)
{

    int soc = -1;
    soc = socket(AF_UNIX, SOCK_STREAM, 0);
    if (soc < 0)
    {
        perror("socket");
        return 1;
    }
    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/test-socket");
    if (bind(soc, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        return 1;
    }
    if (listen(soc, 5) < 0)
    {
        perror("listen");
        return 1;
    }

    using namespace nglab::libssha;
    auto &key_manager = KeyManager::instance();
    KeyFactory::initializeKeyTypes();
    ExtensionFactory::initializeExtensions();
    KeyManager::setLockProvider(new BotanLockProvider());

    Logger log(Logger::instance(), "test-agent");

    /* install signal handlers so we can exit cleanly and flush gcov data */
    std::signal(SIGINT, stop_handler);
    std::signal(SIGTERM, stop_handler);

    const size_t buffer_size = 256 * 1024;
    uint8_t buffer[buffer_size];
    std::list<TestSession> sessions;
    fd_set fds;
    secure_vector<uint8_t> temp_buffer;
    while (g_running)
    {
        FD_ZERO(&fds);
        FD_SET(soc, &fds);
        int max_fd = soc;
        for (auto &session : sessions)
        {
            FD_SET(session.fd(), &fds);
            if (session.fd() > max_fd)
                max_fd = session.fd();
        }

        auto activity = select(max_fd + 1, &fds, nullptr, nullptr, nullptr);
        if (activity < 0)
        {
            log.error("select() failed");
            break;
        }

        if (FD_ISSET(soc, &fds))
        {
            int client = accept(soc, nullptr, nullptr);
            if (client < 0)
            {
                log.error("accept() failed");
                continue;
            }
            log.debug("Accepted new client: fd={}", client);
            sessions.emplace_back( client);
        }

        for ( auto it = sessions.begin(); it != sessions.end();)
        {
            if (FD_ISSET(it->fd(), &fds))
            {
                ssize_t received = recv(it->fd(), buffer, buffer_size - 1, 0);
                if (received < 0)
                {
                    log.error("recv() failed on fd={}", it->fd());
                    close(it->fd());
                    it=sessions.erase(it);
                    continue;
                }
                if (received == 0)
                {
                    log.debug("Client disconnected: fd={}", it->fd());
                    close(it->fd());
                    it=sessions.erase(it);
                    continue;
                }

                log.vdebug("Received {} bytes from fd={}", received, it->fd());
                if (!it->process(buffer, received))
                {
                    log.error("Processing message failed on fd={}", it->fd());
                }

                ++it;
            }
            else
            {
                ++it;
            }
        }
    }

    /* cleanup: close sockets so atexit handlers run cleanly */
    close(soc);
    for (auto &session : sessions)
    {
        close(session.fd());
    }

    return 0;
}