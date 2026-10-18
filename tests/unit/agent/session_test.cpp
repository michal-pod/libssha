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
#include <libssha/agent/session.h>
#include <libssha/extensions/extension-factory.h>
#include <libssha/extensions/extension.h>
#include <libssha/key/key-manager.h>
#include <libssha/key/key-manager-observer.h>
#include <libssha/messages/message.h>
#include <libssha/messages/sign-request.h>
#include <libssha/utils/deserializer.h>
#include <libssha/utils/serializer.h>
#include <botan/ed25519.h>
#include <botan/pubkey.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using nglab::libssha::KeyManager;
using nglab::libssha::Session;
using nglab::libssha::secure_vector;

namespace nglab::libssha::test::session
{
    using Bytes = std::vector<uint8_t>;

    class RecordingSession : public Session
    {
    public:
        explicit RecordingSession(bool async) : LogEnabler("recording-session"), Session()
        {
            m_async_operation = async;
        }

        ~RecordingSession()
        {
            joinWorkers();
        }

        bool confirmRequest([[maybe_unused]] const KeyBase &key) override
        {
            ++m_confirmations;
            return m_confirm_answer;
        }

        void setConfirmAnswer(bool answer) { m_confirm_answer = answer; }
        int confirmations() const { return m_confirmations; }

        bool requiresConfirmation(const KeyBasePtr) const override { return false; }
        std::string client() const override { return "recording-client"; }
        bool processExtensionMessage([[maybe_unused]] const ExtensionMessage &msg) override { return false; }

        bool send(secure_vector<uint8_t> &data) override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_responses.emplace_back(data.begin(), data.end());
            return true;
        }

        std::vector<Bytes> responses() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_responses;
        }

        bool process(const Bytes &data)
        {
            return Session::process(data.data(), data.size());
        }

        // Asynchronous replies arrive from the worker thread
        std::vector<Bytes> waitForResponses(size_t count) const
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (responses().size() < count && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            return responses();
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<Bytes> m_responses;
        std::atomic<bool> m_confirm_answer{true};
        std::atomic<int> m_confirmations{0};
    };

    class CountingObserver : public KeyManagerObserver
    {
    public:
        CountingObserver() { KeyManager::registerObserver(this); }
        ~CountingObserver() { KeyManager::unregisterObserver(this); }

        void onKeyAdded(KeyBasePtr) override {}
        void onKeyRemoved(KeyBasePtr) override {}
        void onKeysCleared() override {}
        void onKeyUsed(KeyBasePtr, const Session *) override { ++used; }
        void onKeyDeclined(KeyBasePtr, const Session *) override { ++declined; }
        void onLocked() override {}
        void onUnlocked() override {}

        std::atomic<int> used{0};
        std::atomic<int> declined{0};
    };

    Bytes frame(const Bytes &body)
    {
        const auto length = static_cast<uint32_t>(body.size());
        Bytes result{static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                     static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
        result.insert(result.end(), body.begin(), body.end());
        return result;
    }

    Bytes extensionFrame(const std::string &name)
    {
        const auto length = static_cast<uint32_t>(name.size());
        Bytes body{SSH_AGENTC_EXTENSION, static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                   static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
        body.insert(body.end(), name.begin(), name.end());
        return frame(body);
    }

    Bytes concat(const Bytes &first, const Bytes &second)
    {
        Bytes result(first);
        result.insert(result.end(), second.begin(), second.end());
        return result;
    }

    const Bytes FailureReply{0, 0, 0, 1, SSH_AGENT_FAILURE};
    const Bytes SuccessReply{0, 0, 0, 1, SSH_AGENT_SUCCESS};
    const Bytes ExtensionFailureReply{0, 0, 0, 1, SSH_AGENT_EXTENSION_FAILURE};
    const Bytes EmptyIdentitiesReply{0, 0, 0, 5, SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0};
    const Bytes UnknownRequest = frame({0xF0}); // 240-255 are private use (RFC 9987, section 8.1.1)
    const std::string Passphrase = "session-test";
    const Bytes SignedData{'d', 'a', 't', 'a'};

    // Ed25519 key derived from a fixed seed, so the public part matches the private one
    struct TestKey
    {
        Bytes seed;
        Bytes pub;
        Bytes pubBlob; // RFC 9987, section 5.3
    };

    TestKey ed25519Key(uint8_t seedByte)
    {
        TestKey key;
        key.seed = Bytes(32, seedByte);
        key.pub = Botan::Ed25519_PrivateKey::from_seed(key.seed).public_key_bits();
        Serializer s;
        s.writeString("ssh-ed25519");
        s.writeBlob(key.pub);
        key.pubBlob = s.data();
        return key;
    }

    // RFC 9987, sections 5.2.3 and 5.2.7, `constraints` fills the part after the comment
    template <typename Fn>
    Bytes addIdentityFrame(uint8_t type, const std::string &keyType, const TestKey &key, Fn constraints)
    {
        Serializer s;
        s.writeByte(type);
        s.writeString(keyType);
        s.writeBlob(key.pub);
        Bytes privateKey(key.seed);
        privateKey.insert(privateKey.end(), key.pub.begin(), key.pub.end());
        s.writeBlob(privateKey);
        s.writeString("test-key");
        constraints(s);
        return frame(s.data());
    }

    Bytes addIdentityFrame(const TestKey &key)
    {
        return addIdentityFrame(SSH_AGENTC_ADD_IDENTITY, "ssh-ed25519", key, [](Serializer &) {});
    }

    Bytes addConfirmedIdentityFrame(const TestKey &key)
    {
        return addIdentityFrame(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, "ssh-ed25519", key,
                                [](Serializer &s) { s.writeByte(SSH_AGENT_CONSTRAIN_CONFIRM); });
    }

    Bytes keyBlobFrame(uint8_t type, const Bytes &keyBlob)
    {
        Serializer s;
        s.writeByte(type);
        s.writeBlob(keyBlob);
        return frame(s.data());
    }

    Bytes signFrame(const Bytes &keyBlob, uint32_t flags = 0)
    {
        Serializer s;
        s.writeByte(SSH_AGENTC_SIGN_REQUEST);
        s.writeBlob(keyBlob);
        s.writeBlob(SignedData);
        s.writeBE32(flags);
        return frame(s.data());
    }

    Bytes passphraseFrame(uint8_t type, const std::string &passphrase)
    {
        Serializer s;
        s.writeByte(type);
        s.writeString(passphrase);
        return frame(s.data());
    }

    Bytes identitiesReply(const TestKey &key)
    {
        Serializer s;
        s.writeByte(SSH_AGENT_IDENTITIES_ANSWER);
        s.writeBE32(1);
        s.writeBlob(key.pubBlob);
        s.writeString("test-key");
        return frame(s.data());
    }

    // Checks that `reply` is SSH_AGENT_SIGN_RESPONSE with a valid signature of SignedData
    void expectValidSignature(const Bytes &reply, const TestKey &key)
    {
        ASSERT_GT(reply.size(), 5u);
        ASSERT_EQ(reply[4], SSH_AGENT_SIGN_RESPONSE);
        Deserializer response(reply.data() + 5, reply.size() - 5);
        const Bytes signatureBlob = response.readBlob();
        Deserializer signature(signatureBlob.data(), signatureBlob.size());
        EXPECT_EQ(signature.readString(), "ssh-ed25519");
        const Bytes signatureBits = signature.readBlob();

        Botan::Ed25519_PublicKey publicKey(key.pub);
        Botan::PK_Verifier verifier(publicKey, "");
        EXPECT_TRUE(verifier.verify_message(SignedData, signatureBits));
    }

    constexpr char unhandled_ext_name[] = "unhandled@example.com";

    // Registered in the factory, but RecordingSession does not handle it
    class UnhandledExtension : public Extension<UnhandledExtension, unhandled_ext_name, ExtensionType::MessageExtension>
    {
    public:
        void serialize([[maybe_unused]] Serializer &s) const override {}
        void deserialize([[maybe_unused]] Deserializer &d) override {}
    };

    class SessionTestFixture : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            ExtensionFactory::initializeExtensions();
            UnhandledExtension::registerType();
            KeyManager::instance().removeAllKeys();
        }

        void TearDown() override
        {
            auto &km = KeyManager::instance();
            if (km.isLocked())
            {
                km.unlock(passphrase());
            }
            km.removeAllKeys();
        }

        static secure_vector<uint8_t> passphrase()
        {
            return secure_vector<uint8_t>(Passphrase.begin(), Passphrase.end());
        }
    };

    // RFC 9987, section 5: a message is a uint32 length followed by the type and contents
    TEST_F(SessionTestFixture, FragmentedMessageIsAnsweredOnce)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(Bytes(UnknownRequest.begin(), UnknownRequest.begin() + 2)));
        EXPECT_TRUE(session.responses().empty());

        ASSERT_TRUE(session.process(Bytes(UnknownRequest.begin() + 2, UnknownRequest.end())));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{FailureReply});
    }

    // RFC 9987, section 3: replies are sent in order
    TEST_F(SessionTestFixture, ConcatenatedMessagesAreAnsweredInOrder)
    {
        RecordingSession session(false);
        const Bytes requestIdentities = frame({SSH_AGENTC_REQUEST_IDENTITIES});

        ASSERT_TRUE(session.process(concat(requestIdentities, UnknownRequest)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{EmptyIdentitiesReply, FailureReply}));
    }

    // RFC 9987, section 3: replies are sent in order, also when the worker thread answers
    TEST_F(SessionTestFixture, AsyncRepliesKeepRequestOrder)
    {
        RecordingSession session(true);
        const Bytes requestIdentities = frame({SSH_AGENTC_REQUEST_IDENTITIES});
        const Bytes removeAll = frame({SSH_AGENTC_REMOVE_ALL_IDENTITIES});

        ASSERT_TRUE(session.process(concat(concat(requestIdentities, UnknownRequest), concat(removeAll, requestIdentities))));
        EXPECT_EQ(session.waitForResponses(4),
                  (std::vector<Bytes>{EmptyIdentitiesReply, FailureReply, SuccessReply, EmptyIdentitiesReply}));
    }

    // RFC 9987 sets no size limit, the connection is closed above Session::MaxMessageLength
    TEST_F(SessionTestFixture, OversizedMessageIsRejected)
    {
        RecordingSession session(false);
        const auto length = static_cast<uint32_t>(Session::MaxMessageLength + 1);
        const Bytes header{static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                           static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};

        EXPECT_FALSE(session.process(header));
        EXPECT_TRUE(session.responses().empty());
    }

    // RFC 9987, section 5: the length covers at least the type byte
    TEST_F(SessionTestFixture, EmptyMessageIsRejected)
    {
        RecordingSession session(false);

        EXPECT_FALSE(session.process(Bytes{0, 0, 0, 0}));
    }

    TEST_F(SessionTestFixture, StoppedSessionRejectsData)
    {
        RecordingSession session(true);
        session.stopProcessing();

        EXPECT_FALSE(session.process(UnknownRequest));
        EXPECT_FALSE(session.hasPendingOperations());
    }

    // RFC 9987, section 5.7: a locked agent suspends sensitive operations, the empty list follows OpenSSH
    TEST_F(SessionTestFixture, LockedAgentListsNoKeysAndRefusesOtherRequests)
    {
        RecordingSession session(false);
        KeyManager::instance().lock(passphrase());

        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REQUEST_IDENTITIES})));
        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REMOVE_ALL_IDENTITIES})));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{EmptyIdentitiesReply, FailureReply}));
    }

    // RFC 9987, section 5.8: an unsupported extension gets an empty FAILURE
    TEST_F(SessionTestFixture, UnsupportedExtensionDoesNotFailBinding)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(extensionFrame("unknown@example.com")));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{FailureReply});
        EXPECT_FALSE(session.bindingFailed());
    }

    TEST_F(SessionTestFixture, ReservedSshv1TypeIsRefused)
    {
        RecordingSession session(false);
        // 9 was REMOVE_ALL_RSA_IDENTITIES in SSHv1, RFC 9987 section 8.1.1 reserves it
        ASSERT_TRUE(session.process(frame({9})));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{FailureReply});
    }

    TEST_F(SessionTestFixture, SmartcardRequestsAreRefused)
    {
        RecordingSession session(false);
        // RFC 9987, sections 5.2.6 and 5.4: an agent without token support MUST reply FAILURE
        for (uint8_t type : {SSH_AGENTC_ADD_SMARTCARD_KEY, SSH_AGENTC_REMOVE_SMARTCARD_KEY, SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED})
        {
            ASSERT_TRUE(session.process(frame({type})));
        }
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{FailureReply, FailureReply, FailureReply}));
    }

    // RFC 9987, section 5.8: a failure of a supported extension SHOULD use SSH_AGENT_EXTENSION_FAILURE
    TEST_F(SessionTestFixture, UnhandledKnownExtensionGetsExtensionFailure)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(extensionFrame(unhandled_ext_name)));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{ExtensionFailureReply});
        EXPECT_FALSE(session.bindingFailed());
    }

    // RFC 9987, section 5.8.1: query answers with the names of supported extensions
    TEST_F(SessionTestFixture, QueryListsRegisteredExtensions)
    {
        RecordingSession session(false);
        const auto lengthPrefixed = [](const std::string &name)
        {
            const auto length = static_cast<uint32_t>(name.size());
            std::string result{static_cast<char>(length >> 24), static_cast<char>(length >> 16),
                               static_cast<char>(length >> 8), static_cast<char>(length)};
            return result + name;
        };

        ASSERT_TRUE(session.process(extensionFrame("query")));

        const auto responses = session.responses();
        ASSERT_EQ(responses.size(), 1u);
        const std::string reply(responses[0].begin(), responses[0].end());
        // Length, type, then the echoed name; other tests may register more extensions
        ASSERT_GT(reply.size(), 5u);
        EXPECT_EQ(static_cast<uint8_t>(reply[4]), SSH_AGENT_EXTENSION_RESPONSE);
        EXPECT_EQ(reply.compare(5, 9, lengthPrefixed("query")), 0);
        for (const char *name : {"query", "restrict-destination-v00@openssh.com", "session-bind@openssh.com"})
        {
            EXPECT_NE(reply.find(lengthPrefixed(name), 14), std::string::npos) << name;
        }
    }

    // RFC 9987, section 5.8.1: the query request has no data after the name
    TEST_F(SessionTestFixture, QueryWithDataIsRefused)
    {
        RecordingSession session(false);
        Bytes request = extensionFrame("query");
        request.push_back(0);
        request[3] += 1; // frame length

        ASSERT_TRUE(session.process(request));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{ExtensionFailureReply});
    }

    // session-bind@openssh.com comes from OpenSSH PROTOCOL.agent, the reply from RFC 9987, section 5.8
    TEST_F(SessionTestFixture, MalformedSessionBindFailsBinding)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(extensionFrame("session-bind@openssh.com")));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{ExtensionFailureReply});
        EXPECT_TRUE(session.bindingFailed());
    }

    // RFC 9987, sections 5.2 and 5.5: SUCCESS for a loaded key, which is then listed
    TEST_F(SessionTestFixture, AddedIdentityIsListed)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addIdentityFrame(key)));
        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REQUEST_IDENTITIES})));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{SuccessReply, identitiesReply(key)}));
    }

    // RFC 9987, section 5.2: FAILURE for an unrecognised key type
    TEST_F(SessionTestFixture, UnknownKeyTypeIsRefused)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(addIdentityFrame(SSH_AGENTC_ADD_IDENTITY, "unknown@example.com", ed25519Key(1),
                                                     [](Serializer &) {})));
        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REQUEST_IDENTITIES})));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{FailureReply, EmptyIdentitiesReply}));
    }

    // RFC 9987, section 5.2.7: an unrecognised constraint refuses the whole request
    TEST_F(SessionTestFixture, UnknownConstraintIsRefused)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);
        const auto addConstrained = [&key](auto constraints)
        { return addIdentityFrame(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, "ssh-ed25519", key, constraints); };

        // 0 is reserved (section 8.2), 3 is not assigned
        ASSERT_TRUE(session.process(addConstrained([](Serializer &s) { s.writeByte(0); })));
        ASSERT_TRUE(session.process(addConstrained([](Serializer &s) { s.writeByte(3); })));
        ASSERT_TRUE(session.process(addConstrained([](Serializer &s)
                                                   {
                                                       s.writeByte(SSH_AGENT_CONSTRAIN_EXTENSION);
                                                       s.writeString("unknown@example.com");
                                                   })));
        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REQUEST_IDENTITIES})));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{FailureReply, FailureReply, FailureReply, EmptyIdentitiesReply}));
    }

    // RFC 9987, section 5.2: re-adding a key replaces its constraints
    TEST_F(SessionTestFixture, ReAddedKeyReplacesConstraints)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addConfirmedIdentityFrame(key)));
        ASSERT_TRUE(session.process(addIdentityFrame(key)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));

        const auto responses = session.responses();
        ASSERT_EQ(responses.size(), 3u);
        EXPECT_EQ(responses[1], SuccessReply);
        expectValidSignature(responses[2], key);
        EXPECT_EQ(session.confirmations(), 0);
    }

    // RFC 9987, section 5.4: SUCCESS when the key was deleted, FAILURE when it was not found
    TEST_F(SessionTestFixture, RemoveIdentityRemovesOnlyKnownKey)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addIdentityFrame(key)));
        ASSERT_TRUE(session.process(keyBlobFrame(SSH_AGENTC_REMOVE_IDENTITY, key.pubBlob)));
        ASSERT_TRUE(session.process(keyBlobFrame(SSH_AGENTC_REMOVE_IDENTITY, key.pubBlob)));
        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REQUEST_IDENTITIES})));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{SuccessReply, SuccessReply, FailureReply, EmptyIdentitiesReply}));
    }

    // RFC 9987, section 5.6: SSH_AGENT_SIGN_RESPONSE with the signature
    TEST_F(SessionTestFixture, SignRequestIsAnswered)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addIdentityFrame(key)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));

        const auto responses = session.responses();
        ASSERT_EQ(responses.size(), 2u);
        expectValidSignature(responses[1], key);
    }

    // RFC 9987, section 5.6: FAILURE when there is no such key
    TEST_F(SessionTestFixture, SignRequestForUnknownKeyFails)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(addIdentityFrame(ed25519Key(1))));
        ASSERT_TRUE(session.process(signFrame(ed25519Key(2).pubBlob)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{SuccessReply, FailureReply}));
    }

    // RFC 9987, sections 5.6 and 5.6.1: unsupported flags get FAILURE, without asking the user
    TEST_F(SessionTestFixture, SignRequestWithUnsupportedFlagsFails)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addConfirmedIdentityFrame(key)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob, SSH_AGENT_RSA_SHA2_256)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{SuccessReply, FailureReply}));
        EXPECT_EQ(session.confirmations(), 0);
    }

    // RFC 9987, sections 5.2.7.2 and 5.6: FAILURE when the user declines the confirmation
    TEST_F(SessionTestFixture, DeclinedConfirmationFailsSignRequest)
    {
        RecordingSession session(false);
        CountingObserver observer;
        const auto key = ed25519Key(1);
        session.setConfirmAnswer(false);

        ASSERT_TRUE(session.process(addConfirmedIdentityFrame(key)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{SuccessReply, FailureReply}));
        EXPECT_EQ(session.confirmations(), 1);
        EXPECT_EQ(observer.declined, 1);
        EXPECT_EQ(observer.used, 0);
    }

    // RFC 9987, section 5.2.7.2: each private key operation is confirmed
    TEST_F(SessionTestFixture, ConfirmedSignRequestIsAnswered)
    {
        RecordingSession session(false);
        CountingObserver observer;
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addConfirmedIdentityFrame(key)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));

        const auto responses = session.responses();
        ASSERT_EQ(responses.size(), 3u);
        expectValidSignature(responses[1], key);
        expectValidSignature(responses[2], key);
        EXPECT_EQ(session.confirmations(), 2);
        EXPECT_EQ(observer.used, 2);
        EXPECT_EQ(observer.declined, 0);
    }

    // RFC 9987, section 5.7: FAILURE when locking a locked agent
    TEST_F(SessionTestFixture, LockingLockedAgentFails)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_LOCK, Passphrase)));
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_LOCK, Passphrase)));
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_UNLOCK, Passphrase)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{SuccessReply, FailureReply, SuccessReply}));
        EXPECT_FALSE(KeyManager::instance().isLocked());
    }

    // RFC 9987, section 5.7: FAILURE when the agent is not locked or the passphrase does not match
    TEST_F(SessionTestFixture, UnlockNeedsLockedAgentAndSamePassphrase)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_UNLOCK, Passphrase)));
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_LOCK, Passphrase)));
        // One failed attempt only, more would start the unlock delay (section 10)
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_UNLOCK, "wrong")));
        EXPECT_TRUE(KeyManager::instance().isLocked());
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_UNLOCK, Passphrase)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{FailureReply, SuccessReply, FailureReply, SuccessReply}));
        EXPECT_FALSE(KeyManager::instance().isLocked());
    }

    // RFC 9987, section 5.7: a locked agent MUST suspend signing, the key works again after unlocking
    TEST_F(SessionTestFixture, LockedAgentRefusesSignRequest)
    {
        RecordingSession session(false);
        const auto key = ed25519Key(1);

        ASSERT_TRUE(session.process(addIdentityFrame(key)));
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_LOCK, Passphrase)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));
        ASSERT_TRUE(session.process(passphraseFrame(SSH_AGENTC_UNLOCK, Passphrase)));
        ASSERT_TRUE(session.process(signFrame(key.pubBlob)));

        const auto responses = session.responses();
        ASSERT_EQ(responses.size(), 5u);
        EXPECT_EQ((std::vector<Bytes>(responses.begin(), responses.begin() + 4)),
                  (std::vector<Bytes>{SuccessReply, SuccessReply, FailureReply, SuccessReply}));
        expectValidSignature(responses[4], key);
    }
}
