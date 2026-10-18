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
#include <botan/ed25519.h>
#include <botan/pubkey.h>
#include <libssha/agent/session.h>
#include <libssha/key/key-manager.h>
#include <libssha/key/key-manager-observer.h>
#include <libssha/messages/message.h>
#include <libssha/messages/sign-request.h>
#include <libssha/utils/deserializer.h>
#include <libssha/utils/serializer.h>
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Session and request helpers shared by the agent tests
namespace nglab::libssha::test::agent
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

        // Bindings that the protocol would refuse, to test KeyBase::permitted directly
        void addBinding(const SessionBinding &binding) { m_session_bindings.push_back(binding); }

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

    inline Bytes frame(const Bytes &body)
    {
        const auto length = static_cast<uint32_t>(body.size());
        Bytes result{static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                     static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
        result.insert(result.end(), body.begin(), body.end());
        return result;
    }

    inline Bytes extensionFrame(const std::string &name)
    {
        const auto length = static_cast<uint32_t>(name.size());
        Bytes body{SSH_AGENTC_EXTENSION, static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                   static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};
        body.insert(body.end(), name.begin(), name.end());
        return frame(body);
    }

    inline Bytes concat(const Bytes &first, const Bytes &second)
    {
        Bytes result(first);
        result.insert(result.end(), second.begin(), second.end());
        return result;
    }

    inline const Bytes FailureReply{0, 0, 0, 1, SSH_AGENT_FAILURE};
    inline const Bytes SuccessReply{0, 0, 0, 1, SSH_AGENT_SUCCESS};
    inline const Bytes ExtensionFailureReply{0, 0, 0, 1, SSH_AGENT_EXTENSION_FAILURE};
    inline const Bytes EmptyIdentitiesReply{0, 0, 0, 5, SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0};
    inline const Bytes SignedData{'d', 'a', 't', 'a'};

    // Ed25519 key derived from a fixed seed, so the public part matches the private one
    struct TestKey
    {
        Bytes seed;
        Bytes pub;
        Bytes pubBlob; // RFC 9987, section 5.3
    };

    inline TestKey ed25519Key(uint8_t seedByte)
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
    inline Bytes addIdentityFrame(uint8_t type, const std::string &keyType, const TestKey &key, Fn constraints)
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

    inline Bytes addIdentityFrame(const TestKey &key)
    {
        return addIdentityFrame(SSH_AGENTC_ADD_IDENTITY, "ssh-ed25519", key, [](Serializer &) {});
    }

    inline Bytes addConfirmedIdentityFrame(const TestKey &key)
    {
        return addIdentityFrame(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, "ssh-ed25519", key,
                                [](Serializer &s) { s.writeByte(SSH_AGENT_CONSTRAIN_CONFIRM); });
    }

    inline Bytes keyBlobFrame(uint8_t type, const Bytes &keyBlob)
    {
        Serializer s;
        s.writeByte(type);
        s.writeBlob(keyBlob);
        return frame(s.data());
    }

    inline Bytes signFrame(const Bytes &keyBlob, uint32_t flags = 0)
    {
        Serializer s;
        s.writeByte(SSH_AGENTC_SIGN_REQUEST);
        s.writeBlob(keyBlob);
        s.writeBlob(SignedData);
        s.writeBE32(flags);
        return frame(s.data());
    }

    inline Bytes passphraseFrame(uint8_t type, const std::string &passphrase)
    {
        Serializer s;
        s.writeByte(type);
        s.writeString(passphrase);
        return frame(s.data());
    }

    inline Bytes identitiesReply(const TestKey &key)
    {
        Serializer s;
        s.writeByte(SSH_AGENT_IDENTITIES_ANSWER);
        s.writeBE32(1);
        s.writeBlob(key.pubBlob);
        s.writeString("test-key");
        return frame(s.data());
    }

    // Checks that `reply` is SSH_AGENT_SIGN_RESPONSE with a valid signature of SignedData
    inline void expectValidSignature(const Bytes &reply, const TestKey &key)
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
} // namespace nglab::libssha::test::agent
