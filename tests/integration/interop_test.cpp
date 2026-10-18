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
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

// Encodings and signatures checked by OpenSSH itself, not by libssha code
namespace nglab::libssha::test::integration
{
    using ::testing::HasSubstr;

    namespace detail
    {
        std::string publicKey(const std::string &pubFile)
        {
            std::ifstream in(pubFile);
            std::string type;
            std::string base64;
            in >> type >> base64;
            return type + " " + base64;
        }
    }

    class KeyInteropTest : public AgentIntegration, public ::testing::WithParamInterface<std::string>
    {
    };

    // RFC 9987, section 5.3: the agent lists the same public key blob that was added
    TEST_P(KeyInteropTest, ListedPublicKeyMatchesFile)
    {
        ASSERT_EQ(sshAddKey(GetParam()).exitCode, 0);
        auto list = sshAdd({"-L"});
        EXPECT_EQ(list.exitCode, 0);
        EXPECT_THAT(list.out, HasSubstr(detail::publicKey(m_env->userKey(GetParam()) + ".pub")));
    }

    // ssh-add -T signs random data with the agent and verifies the signature
    TEST_P(KeyInteropTest, OpenSshVerifiesSignature)
    {
        ASSERT_EQ(sshAddKey(GetParam()).exitCode, 0);
        auto result = sshAdd({"-T", m_env->userKey(GetParam()) + ".pub"});
        EXPECT_EQ(result.exitCode, 0) << result.output();
    }

    // SSHSIG as used by ssh-keygen -Y and git, data other than a user authentication
    TEST_P(KeyInteropTest, SshsigSignatureVerifies)
    {
        ASSERT_EQ(sshAddKey(GetParam()).exitCode, 0);

        // Only the public key, so ssh-keygen has to sign with the agent
        const std::string pubKey = m_env->path("agent-only.pub");
        std::filesystem::copy_file(m_env->userKey(GetParam()) + ".pub", pubKey);
        const std::string data = m_env->path("data");
        std::ofstream(data) << "signed data\n";
        std::ofstream(m_env->path("allowed_signers")) << "tester " << detail::publicKey(pubKey) << "\n";

        auto sign = sshKeygen({"-Y", "sign", "-f", pubKey, "-n", "test", data});
        ASSERT_EQ(sign.exitCode, 0) << sign.output();
        auto verify = sshKeygen({"-Y", "verify", "-f", m_env->path("allowed_signers"), "-I", "tester", "-n", "test", "-s",
                                 data + ".sig"},
                                data);
        EXPECT_EQ(verify.exitCode, 0) << verify.output();
    }

    INSTANTIATE_TEST_SUITE_P(KeyTypes, KeyInteropTest, ::testing::ValuesIn(UserKeyNames),
                             [](const auto &info) { return info.param; });

    // Signing a destination constrained key outside of a bound user authentication
    TEST_F(AgentIntegration, ConstrainedKeyRefusesSshsig)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a"}).exitCode, 0);
        const std::string pubKey = m_env->path("agent-only.pub");
        std::filesystem::copy_file(m_env->userKey("ed25519") + ".pub", pubKey);
        const std::string data = m_env->path("data");
        std::ofstream(data) << "signed data\n";

        auto sign = sshKeygen({"-Y", "sign", "-f", pubKey, "-n", "test", data});
        EXPECT_NE(sign.exitCode, 0) << sign.output();
    }

    // RFC 9987, section 5.6.1: the flags of ssh-rsa select the signature algorithm
    class RsaAlgorithmTest : public AgentIntegration, public ::testing::WithParamInterface<std::string>
    {
    };

    TEST_P(RsaAlgorithmTest, ServerAcceptsSignature)
    {
        ASSERT_EQ(sshAddKey("rsa").exitCode, 0);
        auto result = ssh({"host_a"}, "echo connected_to_host_a", {"-o", "PubkeyAcceptedAlgorithms=" + GetParam()});
        EXPECT_THAT(result.output(), HasSubstr("connected_to_host_a"));
    }

    INSTANTIATE_TEST_SUITE_P(Algorithms, RsaAlgorithmTest, ::testing::Values("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"),
                             [](const auto &info)
                             {
                                 std::string name = info.param;
                                 std::replace(name.begin(), name.end(), '-', '_');
                                 return name;
                             });

    // The session-bind carries a signature made by the host key, one per host key type
    class HostKeyTypeTest : public AgentIntegration, public ::testing::WithParamInterface<std::string>
    {
    };

    TEST_P(HostKeyTypeTest, SessionBindWithHostKeyType)
    {
        ASSERT_EQ(sshAddKey("ed25519", {"host_a"}).exitCode, 0);
        auto result = ssh({"host_a"}, "echo connected_to_host_a", {"-o", "HostKeyAlgorithms=" + GetParam()});
        EXPECT_THAT(result.output(), HasSubstr("connected_to_host_a"));
    }

    INSTANTIATE_TEST_SUITE_P(HostKeys, HostKeyTypeTest,
                             ::testing::Values("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                                               "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"),
                             [](const auto &info)
                             {
                                 std::string name = info.param;
                                 std::replace(name.begin(), name.end(), '-', '_');
                                 return name;
                             });

    // RFC 9987, sections 5.2 and 5.3: the comment comes back as it was added
    TEST_F(AgentIntegration, CommentIsListedUnchanged)
    {
        const std::string comment = "zażółć gęślą jaźń <tester@example.com>";
        ASSERT_EQ(sshAdd({generateKey("commented", comment)}).exitCode, 0);
        EXPECT_THAT(sshAdd({"-l"}).out, HasSubstr(" " + comment + " (ED25519)"));
        EXPECT_THAT(sshAdd({"-L"}).out, HasSubstr(" " + comment + "\n"));
    }
}
