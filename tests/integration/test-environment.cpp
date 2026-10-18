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
#include "test-environment.h"
#include "integration-config.h"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace nglab::libssha::test::integration
{
    namespace detail
    {
        std::string readFile(const fs::path &file)
        {
            std::ifstream in(file);
            if (!in)
            {
                throw std::runtime_error("Cannot read " + file.string());
            }
            std::stringstream ss;
            ss << in.rdbuf();
            return ss.str();
        }

        // "type base64 comment" -> "type base64"
        std::string keyWithoutComment(const std::string &pubKey)
        {
            auto first = pubKey.find(' ');
            auto second = pubKey.find_first_of(" \n", first + 1);
            return pubKey.substr(0, second);
        }
    }

    TestEnvironment::TestEnvironment()
    {
        // The socket path must fit in sun_path, a build directory may be too deep
        std::string pattern = "/tmp/libssha-it-XXXXXX";
        if (mkdtemp(pattern.data()) == nullptr)
        {
            throw std::runtime_error("mkdtemp: " + std::string(std::strerror(errno)));
        }
        m_dir = pattern;

        for (const auto &key : KeyNames)
        {
            copyKey("user_test_" + key);
            for (const auto &host : Hosts)
            {
                copyKey(host + "_" + key);
            }
        }
        for (const auto &host : Hosts)
        {
            writeSshdConfig(host);
        }
        writeSshConfig();
        writeKnownHosts();
        writeAuthorizedKeys();
    }

    TestEnvironment::~TestEnvironment()
    {
        if (m_keep || std::getenv("LIBSSHA_KEEP_TEST_DIR") != nullptr)
        {
            return;
        }
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }

    void TestEnvironment::copyKey(const std::string &file)
    {
        const fs::path source(KEYS_DIR);
        fs::copy_file(source / file, m_dir / file);
        fs::copy_file(source / (file + ".pub"), m_dir / (file + ".pub"));
        // ssh and sshd refuse private keys readable by others
        fs::permissions(m_dir / file, fs::perms::owner_read | fs::perms::owner_write);
    }

    void TestEnvironment::writeFile(const std::string &name, const std::string &contents)
    {
        std::ofstream out(m_dir / name);
        out << contents;
        if (!out)
        {
            throw std::runtime_error("Cannot write " + path(name));
        }
    }

    void TestEnvironment::writeSshdConfig(const std::string &host)
    {
        std::ostringstream conf;
        for (const auto &key : KeyNames)
        {
            conf << "HostKey " << path(host + "_" + key) << "\n";
        }
        conf << "AuthorizedKeysFile " << path("authorized_keys") << "\n"
             << "PubkeyAuthentication yes\n"
             << "PasswordAuthentication no\n"
             << "KbdInteractiveAuthentication no\n"
             << "UsePAM no\n"
             << "HostKeyAlgorithms +ssh-rsa\n"
             // SHA-1 RSA signatures are off by default, a test checks the agent still makes them
             << "PubkeyAcceptedAlgorithms +ssh-rsa\n"
             // The temporary directory does not pass the ownership checks of sshd
             << "StrictModes no\n"
             << "PermitUserRC no\n"
             << "PidFile none\n";
        writeFile("sshd_" + host, conf.str());
    }

    void TestEnvironment::writeSshConfig()
    {
        std::ostringstream conf;
        conf << "Host";
        for (const auto &host : Hosts)
        {
            conf << " " << host;
        }
        conf << "\n"
             << "    ProxyCommand " << SSHD_PATH << " -i -f " << path("sshd_%n") << "\n"
             << "    UserKnownHostsFile " << knownHosts() << "\n"
             << "    GlobalKnownHostsFile /dev/null\n"
             << "    StrictHostKeyChecking yes\n"
             << "    UpdateHostKeys no\n"
             << "    BatchMode yes\n"
             << "    ForwardAgent yes\n"
             // Only keys from the agent, never the default ~/.ssh/id_* files
             << "    IdentityFile " << path("no-identity") << "\n";
        writeFile("ssh_config", conf.str());
    }

    void TestEnvironment::writeKnownHosts()
    {
        std::ostringstream hosts;
        for (const auto &host : Hosts)
        {
            for (const auto &key : KeyNames)
            {
                hosts << host << " " << detail::keyWithoutComment(detail::readFile(m_dir / (host + "_" + key + ".pub")))
                      << "\n";
            }
        }
        writeFile("known_hosts", hosts.str());
    }

    void TestEnvironment::writeAuthorizedKeys()
    {
        std::string keys;
        for (const auto &key : KeyNames)
        {
            keys += detail::readFile(m_dir / ("user_test_" + key + ".pub"));
        }
        writeFile("authorized_keys", keys);
    }
}
