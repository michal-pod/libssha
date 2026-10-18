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
#include <fstream>

// OpenSSH certificates, which libssha does not support yet: the tests check what
// the agent does with what it refuses
namespace nglab::libssha::test::integration
{
    using ::testing::HasSubstr;

    class CertificateTest : public AgentIntegration
    {
    protected:
        // A CA key and the certificate of user_test_ed25519 next to the key, as ssh-keygen -s makes it
        void signUserKey()
        {
            const std::string ca = generateKey("user_ca");
            auto sign = sshKeygen({"-q", "-s", ca, "-I", "tester", "-n", userName(), m_env->userKey("ed25519") + ".pub"});
            ASSERT_EQ(sign.exitCode, 0) << sign.output();
        }

        // known_hosts that trusts host_a through a host CA only
        std::string signHostKey()
        {
            const std::string ca = generateKey("host_ca");
            const std::string hostKey = m_env->path("host_a_ed25519");
            auto sign = sshKeygen({"-q", "-s", ca, "-I", "host_a", "-h", "-n", "host_a", hostKey + ".pub"});
            EXPECT_EQ(sign.exitCode, 0) << sign.output();
            m_env->addSshdOption("host_a", "HostCertificate " + hostKey + "-cert.pub");

            const std::string knownHosts = m_env->path("known_hosts_ca");
            std::ifstream caPub(ca + ".pub");
            std::string type;
            std::string base64;
            caPub >> type >> base64;
            std::ofstream(knownHosts) << "@cert-authority host_a " << type << " " << base64 << "\n";
            return knownHosts;
        }
    };

    // ssh-add adds the key and then its certificate, a refused certificate must not
    // take the key with it
    TEST_F(CertificateTest, KeyStaysUsableNextToCertificate)
    {
        signUserKey();
        sshAddKey("ed25519");

        std::ifstream pub(m_env->userKey("ed25519") + ".pub");
        std::string type;
        std::string base64;
        pub >> type >> base64;
        EXPECT_THAT(sshAdd({"-L"}).out, HasSubstr(type + " " + base64));
        EXPECT_THAT(ssh({"host_a"}, "echo connected_to_host_a", {"-o", "PubkeyAcceptedAlgorithms=ssh-ed25519"}).output(),
                    HasSubstr("connected_to_host_a"));
    }

    // restrict-destination-v00@openssh.com: a hop may name its host by a CA key (is_ca).
    // libssha skips such keys, so the hop matches no host and the key stays unusable;
    // OpenSSH shows that the test setup itself is right.
    TEST_F(CertificateTest, HostCaInDestinationConstraint)
    {
        const std::string knownHosts = signHostKey();
        ASSERT_EQ(sshAdd({"-H", knownHosts, "-h", "host_a", m_env->userKey("ed25519")}).exitCode, 0);

        auto login = ssh({"host_a"}, "echo connected_to_host_a",
                         {"-o", "UserKnownHostsFile=" + knownHosts, "-o",
                          "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com"});
        EXPECT_THAT(login.output(), HasSubstr(referenceAgent() ? "connected_to_host_a" : PermissionDenied));
    }
}
