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

#include <filesystem>
#include <string>
#include <vector>

namespace nglab::libssha::test::integration
{
    // Hosts reachable from the tests, each connection starts its own `sshd -i`
    // through ProxyCommand, so no daemon or port outlives a connection
    const std::vector<std::string> Hosts{"host_a", "host_b", "host_c"};

    // Key files generated at build time, without the user_test_/host_x_ prefix
    const std::vector<std::string> KeyNames{"rsa", "ecdsa256", "ecdsa384", "ecdsa521", "ed25519"};

    // Temporary directory with copies of the keys and the ssh/sshd configuration
    class TestEnvironment
    {
    public:
        TestEnvironment();
        ~TestEnvironment();

        TestEnvironment(const TestEnvironment &) = delete;
        TestEnvironment &operator=(const TestEnvironment &) = delete;

        const std::filesystem::path &dir() const { return m_dir; }
        std::string path(const std::string &name) const { return (m_dir / name).string(); }

        std::string sshConfig() const { return path("ssh_config"); }
        std::string knownHosts() const { return path("known_hosts"); }
        std::string agentSocket() const { return path("agent.sock"); }
        std::string agentLog() const { return path("agent.log"); }
        std::string userKey(const std::string &name) const { return path("user_test_" + name); }

        // Leave the directory for inspection after a failed test
        void keep() { m_keep = true; }

    private:
        void copyKey(const std::string &file);
        void writeFile(const std::string &name, const std::string &contents);
        void writeSshdConfig(const std::string &host);
        void writeSshConfig();
        void writeKnownHosts();
        void writeAuthorizedKeys();

        std::filesystem::path m_dir;
        bool m_keep = false;
    };
}
