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
#include <libssha/messages/message.h>
#include <gtest/gtest.h>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using nglab::libssha::KeyManager;
using nglab::libssha::Session;
using nglab::libssha::secure_vector;

namespace nglab::libssha::test
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

        bool confirmRequest([[maybe_unused]] const KeyBase &key) override { return true; }
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
            const std::string text = "session-test";
            return secure_vector<uint8_t>(text.begin(), text.end());
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
}
