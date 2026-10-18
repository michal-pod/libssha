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
#include "recording-session.h"
#include <botan/auto_rng.h>
#include <libssha/extensions/extension-factory.h>
#include <gtest/gtest.h>
#include <string>
#include <vector>

// session-bind@openssh.com and restrict-destination-v00@openssh.com come from
// OpenSSH PROTOCOL.agent, not from RFC 9987. The expected behaviour follows
// process_ext_session_bind(), identity_permitted() and process_sign_request2()
// in OpenSSH ssh-agent.c.
namespace nglab::libssha::test::destination_constraints
{
    using namespace nglab::libssha::test::agent;

    constexpr uint8_t SSH_MSG_USERAUTH_REQUEST = 50;
    const std::string HostboundMethod = "publickey-hostbound-v00@openssh.com";

    const TestKey UserKey = ed25519Key(0x01);
    const TestKey OtherUserKey = ed25519Key(0x02);
    const TestKey HostA = ed25519Key(0xA0);
    const TestKey HostB = ed25519Key(0xB0);
    const TestKey HostC = ed25519Key(0xC0);

    Bytes sessionId(uint8_t value, size_t length = 32)
    {
        return Bytes(length, value);
    }

    // Signature blob: string "ssh-ed25519", string signature
    Bytes sshSignature(const TestKey &key, const Bytes &data)
    {
        Botan::AutoSeeded_RNG rng;
        const auto privateKey = Botan::Ed25519_PrivateKey::from_seed(key.seed);
        Botan::PK_Signer signer(privateKey, rng, "");
        Serializer s;
        s.writeString("ssh-ed25519");
        s.writeBlob(signer.sign_message(data, rng));
        return s.data();
    }

    Bytes sessionBindFrame(const TestKey &host, const Bytes &sid, bool forwarded, const Bytes &signature)
    {
        Serializer s;
        s.writeByte(SSH_AGENTC_EXTENSION);
        s.writeString("session-bind@openssh.com");
        s.writeBlob(host.pubBlob);
        s.writeBlob(sid);
        s.writeBlob(signature);
        s.writeByte(forwarded ? 1 : 0);
        return frame(s.data());
    }

    Bytes sessionBindFrame(const TestKey &host, const Bytes &sid, bool forwarded)
    {
        return sessionBindFrame(host, sid, forwarded, sshSignature(host, sid));
    }

    // Hop descriptor: string user, string hostname, string extensions, (string key, bool ca)*
    Bytes hop(const std::string &user, const std::string &hostname, const TestKey *host)
    {
        Serializer s;
        s.writeString(user);
        s.writeString(hostname);
        s.writeBlob({});
        if (host)
        {
            s.writeBlob(host->pubBlob);
            s.writeByte(0);
        }
        return s.data();
    }

    // One destination as added by ssh-add -h [from>]to, from == nullptr is the first hop
    Bytes destination(const TestKey *from, const TestKey &to, const std::string &toUser = "")
    {
        Serializer s;
        s.writeBlob(from ? hop("", "from-host", from) : hop("", "", nullptr));
        s.writeBlob(hop(toUser, "to-host", &to));
        s.writeBlob({});
        return s.data();
    }

    Bytes addRestrictedFrame(const TestKey &key, const std::vector<Bytes> &destinations)
    {
        return addIdentityFrame(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, "ssh-ed25519", key,
                                [&destinations](Serializer &s)
                                {
                                    Serializer list;
                                    for (const auto &d : destinations)
                                    {
                                        list.writeBlob(d);
                                    }
                                    s.writeByte(SSH_AGENT_CONSTRAIN_EXTENSION);
                                    s.writeString("restrict-destination-v00@openssh.com");
                                    s.writeBlob(list.data());
                                });
    }

    // Data signed for SSH_MSG_USERAUTH_REQUEST, the host key is sent only by the hostbound method
    Bytes userauthRequest(const Bytes &sid, const std::string &user, const TestKey &key, const TestKey *host,
                          const std::string &method = HostboundMethod)
    {
        Serializer s;
        s.writeBlob(sid);
        s.writeByte(SSH_MSG_USERAUTH_REQUEST);
        s.writeString(user);
        s.writeString("ssh-connection");
        s.writeString(method);
        s.writeByte(1);
        s.writeString("ssh-ed25519");
        s.writeBlob(key.pubBlob);
        if (host)
        {
            s.writeBlob(host->pubBlob);
        }
        return s.data();
    }

    Bytes signFrame(const TestKey &key, const Bytes &data)
    {
        Serializer s;
        s.writeByte(SSH_AGENTC_SIGN_REQUEST);
        s.writeBlob(key.pubBlob);
        s.writeBlob(data);
        s.writeBE32(0);
        return frame(s.data());
    }

    bool isSignResponse(const Bytes &reply)
    {
        return reply.size() > 4 && reply[4] == SSH_AGENT_SIGN_RESPONSE;
    }

    uint32_t listedKeys(const Bytes &reply)
    {
        Deserializer d(reply);
        d.readBE32();
        EXPECT_EQ(d.readByte(), SSH_AGENT_IDENTITIES_ANSWER);
        return d.readBE32();
    }

    class DestinationConstraintTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            ExtensionFactory::initializeExtensions();
            KeyManager::instance().removeAllKeys();
        }

        void TearDown() override { KeyManager::instance().removeAllKeys(); }

        // Sends one request and returns its reply
        Bytes request(const Bytes &frame)
        {
            const auto before = m_session.responses().size();
            EXPECT_TRUE(m_session.process(frame));
            const auto responses = m_session.responses();
            EXPECT_EQ(responses.size(), before + 1);
            return responses.empty() ? Bytes{} : responses.back();
        }

        void bind(const TestKey &host, const Bytes &sid, bool forwarded)
        {
            ASSERT_EQ(request(sessionBindFrame(host, sid, forwarded)), SuccessReply);
        }

        void addRestricted(const TestKey &key, const std::vector<Bytes> &destinations)
        {
            ASSERT_EQ(request(addRestrictedFrame(key, destinations)), SuccessReply);
        }

        Bytes sign(const Bytes &data, const TestKey &key = UserKey) { return request(signFrame(key, data)); }

        uint32_t listed() { return listedKeys(request(frame({SSH_AGENTC_REQUEST_IDENTITIES}))); }

        RecordingSession m_session{false};
    };

    // session-bind@openssh.com

    TEST_F(DestinationConstraintTest, SessionBindIsRecorded)
    {
        bind(HostA, sessionId(1), true);
        bind(HostB, sessionId(2), false);

        const auto &bindings = m_session.sessionBindings();
        ASSERT_EQ(bindings.size(), 2u);
        EXPECT_EQ(bindings[0].host_key, HostA.pubBlob);
        EXPECT_EQ(bindings[0].session_id, sessionId(1));
        EXPECT_TRUE(bindings[0].forwarded);
        EXPECT_EQ(bindings[1].host_key, HostB.pubBlob);
        EXPECT_FALSE(bindings[1].forwarded);
        EXPECT_TRUE(m_session.isForwarded());
        EXPECT_FALSE(m_session.bindingFailed());
    }

    TEST_F(DestinationConstraintTest, SessionBindWithBadSignatureFails)
    {
        EXPECT_EQ(request(sessionBindFrame(HostA, sessionId(1), false, sshSignature(HostA, sessionId(2)))),
                  ExtensionFailureReply);
        EXPECT_TRUE(m_session.bindingFailed());
        EXPECT_TRUE(m_session.sessionBindings().empty());
    }

    // The signature proves that the session belongs to the host key
    TEST_F(DestinationConstraintTest, SessionBindWithoutSignatureFails)
    {
        EXPECT_EQ(request(sessionBindFrame(HostA, sessionId(1), false, {})), ExtensionFailureReply);
        EXPECT_TRUE(m_session.bindingFailed());
        EXPECT_TRUE(m_session.sessionBindings().empty());
    }

    // AGENT_MAX_SID_LEN in ssh-agent.c
    TEST_F(DestinationConstraintTest, SessionBindWithLongSessionIdFails)
    {
        bind(HostA, sessionId(1, 128), true);
        EXPECT_EQ(request(sessionBindFrame(HostB, sessionId(2, 129), false)), ExtensionFailureReply);
        EXPECT_EQ(m_session.sessionBindings().size(), 0u);
    }

    TEST_F(DestinationConstraintTest, RepeatedSessionBindIsIgnored)
    {
        bind(HostA, sessionId(1), true);
        bind(HostA, sessionId(1), true);
        EXPECT_EQ(m_session.sessionBindings().size(), 1u);
    }

    TEST_F(DestinationConstraintTest, SessionIdBoundToOtherHostKeyFails)
    {
        bind(HostA, sessionId(1), true);
        EXPECT_EQ(request(sessionBindFrame(HostB, sessionId(1), true)), ExtensionFailureReply);
        EXPECT_TRUE(m_session.bindingFailed());
    }

    // A binding that is not forwarded was made for authentication, nothing may follow it
    TEST_F(DestinationConstraintTest, SessionBindAfterAuthenticationBindFails)
    {
        bind(HostA, sessionId(1), false);
        EXPECT_EQ(request(sessionBindFrame(HostB, sessionId(2), true)), ExtensionFailureReply);
        EXPECT_TRUE(m_session.bindingFailed());
    }

    // AGENT_MAX_SESSION_IDS in ssh-agent.c
    TEST_F(DestinationConstraintTest, SessionBindsAreLimited)
    {
        for (uint8_t i = 1; i <= 16; ++i)
        {
            bind(HostA, sessionId(i), true);
        }
        EXPECT_EQ(request(sessionBindFrame(HostA, sessionId(17), true)), ExtensionFailureReply);
    }

    // Signing with a destination constrained key, one hop

    TEST_F(DestinationConstraintTest, UnboundConnectionRefusesConstrainedKey)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        EXPECT_EQ(sign(userauthRequest(sessionId(1), "user", UserKey, &HostA)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, PermittedHostSigns)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), false);
        EXPECT_TRUE(isSignResponse(sign(userauthRequest(sessionId(1), "user", UserKey, &HostA))));
    }

    TEST_F(DestinationConstraintTest, OtherHostIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostB, sessionId(1), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(1), "user", UserKey, &HostB)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, SessionIdMustBeLastBound)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(2), "user", UserKey, &HostA)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, HostKeyMustBeLastBound)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(nullptr, HostB)});
        bind(HostA, sessionId(1), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(1), "user", UserKey, &HostB)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, UserauthKeyMustBeSigningKey)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(1), "user", OtherUserKey, &HostA)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, TrailingDataAfterUserauthIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), false);
        auto data = userauthRequest(sessionId(1), "user", UserKey, &HostA);
        data.push_back(0);
        EXPECT_EQ(sign(data), FailureReply);
    }

    TEST_F(DestinationConstraintTest, OtherDataIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), false);
        EXPECT_EQ(sign(SignedData), FailureReply);
    }

    // Servers without publickey-hostbound send no host key, the bound one is used
    TEST_F(DestinationConstraintTest, PlainPublickeyOnFirstHopSigns)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), false);
        EXPECT_TRUE(isSignResponse(sign(userauthRequest(sessionId(1), "user", UserKey, nullptr, "publickey"))));
    }

    TEST_F(DestinationConstraintTest, UserConstraintIsChecked)
    {
        addRestricted(UserKey, {destination(nullptr, HostA, "alice")});
        bind(HostA, sessionId(1), false);
        EXPECT_TRUE(isSignResponse(sign(userauthRequest(sessionId(1), "alice", UserKey, &HostA))));
        EXPECT_EQ(sign(userauthRequest(sessionId(1), "mallory", UserKey, &HostA)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, UnconstrainedKeyIgnoresBindings)
    {
        ASSERT_EQ(request(addIdentityFrame(UserKey)), SuccessReply);
        bind(HostA, sessionId(1), false);
        EXPECT_TRUE(isSignResponse(sign(SignedData)));
    }

    TEST_F(DestinationConstraintTest, FailedBindRefusesOnlyConstrainedKeys)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        ASSERT_EQ(request(addIdentityFrame(OtherUserKey)), SuccessReply);
        ASSERT_EQ(request(sessionBindFrame(HostA, sessionId(1), false, {0})), ExtensionFailureReply);

        EXPECT_EQ(sign(userauthRequest(sessionId(1), "user", UserKey, &HostA)), FailureReply);
        EXPECT_TRUE(isSignResponse(sign(SignedData, OtherUserKey)));
    }

    // Forwarded connections

    TEST_F(DestinationConstraintTest, ForwardedHopSigns)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB)});
        bind(HostA, sessionId(1), true);
        bind(HostB, sessionId(2), false);
        EXPECT_TRUE(isSignResponse(sign(userauthRequest(sessionId(2), "user", UserKey, &HostB))));
    }

    TEST_F(DestinationConstraintTest, TwoForwardedHopsSign)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB), destination(&HostB, HostC)});
        bind(HostA, sessionId(1), true);
        bind(HostB, sessionId(2), true);
        bind(HostC, sessionId(3), false);
        EXPECT_TRUE(isSignResponse(sign(userauthRequest(sessionId(3), "user", UserKey, &HostC))));
    }

    TEST_F(DestinationConstraintTest, MissingHopConstraintIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), true);
        bind(HostB, sessionId(2), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(2), "user", UserKey, &HostB)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, SigningOnForwardingHopIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB)});
        bind(HostA, sessionId(1), true);
        EXPECT_EQ(sign(userauthRequest(sessionId(1), "user", UserKey, &HostA)), FailureReply);
    }

    TEST_F(DestinationConstraintTest, CycleIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB)});
        bind(HostA, sessionId(1), true);
        bind(HostB, sessionId(2), true);
        bind(HostA, sessionId(3), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(3), "user", UserKey, &HostA)), FailureReply);
    }

    // A forwarded hop has to send its host key, the plain publickey method is not enough
    TEST_F(DestinationConstraintTest, PlainPublickeyOnForwardedHopIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB)});
        bind(HostA, sessionId(1), true);
        bind(HostB, sessionId(2), false);
        EXPECT_EQ(sign(userauthRequest(sessionId(2), "user", UserKey, nullptr, "publickey")), FailureReply);
    }

    // The protocol refuses this order of bindings, so KeyBase::permitted is checked directly
    TEST_F(DestinationConstraintTest, ForwardingThroughAuthenticationBindIsRefused)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB)});
        m_session.addBinding(SessionBinding(HostA.pubBlob, sessionId(1), false));
        m_session.addBinding(SessionBinding(HostB.pubBlob, sessionId(2), false));

        const auto key = KeyManager::instance().getKey(UserKey.pubBlob);
        ASSERT_NE(key, nullptr);
        EXPECT_FALSE(key->permitted(m_session, "user"));
    }

    // Listing keys

    TEST_F(DestinationConstraintTest, UnboundConnectionListsConstrainedKey)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        EXPECT_EQ(listed(), 1u);
    }

    TEST_F(DestinationConstraintTest, KeyUsableOnlyAtForwardingHostIsHidden)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        bind(HostA, sessionId(1), true);
        EXPECT_EQ(listed(), 0u);
    }

    TEST_F(DestinationConstraintTest, KeyUsableBeyondForwardingHostIsListed)
    {
        addRestricted(UserKey, {destination(nullptr, HostA), destination(&HostA, HostB)});
        bind(HostA, sessionId(1), true);
        EXPECT_EQ(listed(), 1u);
    }

    TEST_F(DestinationConstraintTest, KeyForOtherHostIsHidden)
    {
        addRestricted(UserKey, {destination(nullptr, HostA)});
        ASSERT_EQ(request(addIdentityFrame(OtherUserKey)), SuccessReply);
        bind(HostB, sessionId(1), false);
        EXPECT_EQ(listed(), 1u);
    }
} // namespace nglab::libssha::test::destination_constraints
