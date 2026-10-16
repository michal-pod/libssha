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
    const Bytes EmptyIdentitiesReply{0, 0, 0, 5, SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0};
    const Bytes UnknownRequest = frame({0xF0});

    class SessionTestFixture : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            ExtensionFactory::initializeExtensions();
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

    TEST_F(SessionTestFixture, FragmentedMessageIsAnsweredOnce)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(Bytes(UnknownRequest.begin(), UnknownRequest.begin() + 2)));
        EXPECT_TRUE(session.responses().empty());

        ASSERT_TRUE(session.process(Bytes(UnknownRequest.begin() + 2, UnknownRequest.end())));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{FailureReply});
    }

    TEST_F(SessionTestFixture, ConcatenatedMessagesAreAnsweredInOrder)
    {
        RecordingSession session(false);
        const Bytes requestIdentities = frame({SSH_AGENTC_REQUEST_IDENTITIES});

        ASSERT_TRUE(session.process(concat(requestIdentities, UnknownRequest)));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{EmptyIdentitiesReply, FailureReply}));
    }

    TEST_F(SessionTestFixture, AsyncRepliesKeepRequestOrder)
    {
        RecordingSession session(true);
        const Bytes requestIdentities = frame({SSH_AGENTC_REQUEST_IDENTITIES});
        const Bytes removeAll = frame({SSH_AGENTC_REMOVE_ALL_IDENTITIES});

        ASSERT_TRUE(session.process(concat(concat(requestIdentities, UnknownRequest), concat(removeAll, requestIdentities))));
        EXPECT_EQ(session.waitForResponses(4),
                  (std::vector<Bytes>{EmptyIdentitiesReply, FailureReply, SuccessReply, EmptyIdentitiesReply}));
    }

    TEST_F(SessionTestFixture, OversizedMessageIsRejected)
    {
        RecordingSession session(false);
        const auto length = static_cast<uint32_t>(Session::MaxMessageLength + 1);
        const Bytes header{static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
                           static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length)};

        EXPECT_FALSE(session.process(header));
        EXPECT_TRUE(session.responses().empty());
    }

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

    TEST_F(SessionTestFixture, LockedAgentListsNoKeysAndRefusesOtherRequests)
    {
        RecordingSession session(false);
        KeyManager::instance().lock(passphrase());

        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REQUEST_IDENTITIES})));
        ASSERT_TRUE(session.process(frame({SSH_AGENTC_REMOVE_ALL_IDENTITIES})));
        EXPECT_EQ(session.responses(), (std::vector<Bytes>{EmptyIdentitiesReply, FailureReply}));
    }

    TEST_F(SessionTestFixture, UnsupportedExtensionDoesNotFailBinding)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(extensionFrame("unknown@example.com")));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{FailureReply});
        EXPECT_FALSE(session.bindingFailed());
    }

    TEST_F(SessionTestFixture, MalformedSessionBindFailsBinding)
    {
        RecordingSession session(false);

        ASSERT_TRUE(session.process(extensionFrame("session-bind@openssh.com")));
        EXPECT_EQ(session.responses(), std::vector<Bytes>{FailureReply});
        EXPECT_TRUE(session.bindingFailed());
    }
}
