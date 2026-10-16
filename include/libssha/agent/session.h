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
#pragma once
#include <libssha/utils/logger.h>
#include <libssha/utils/secure_vector.h>
#include <libssha/key/key-manager.h>
#include <cstddef>
#include <cstdint>
#include "match-info.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>

namespace nglab
{
    namespace libssha
    {
        class Message;

        struct SessionBinding
        {
            /**
             * @brief Constructor for SessionBinding
             * @param host_key The host key associated with the session
             * @param session_id The session ID
             * @param forwarded Whether the session is forwarded
             */
            SessionBinding(const std::vector<uint8_t> &host_key, const std::vector<uint8_t> &session_id, bool forwarded)
                : host_key(host_key), session_id(session_id), forwarded(forwarded) {}

            /**
             * @brief Host key associated with the session
             */
            std::vector<uint8_t> host_key;

            /**
             * @brief Session ID
             */
            std::vector<uint8_t> session_id;

            /**
             * @brief Whether the session is forwarded
             */
            bool forwarded;
        };

        class KeyBase;
        class UserAuthRequestMessage;
        class ExtensionMessage;

        /**
         * @brief Represents an SSH agent session.
         *
         * This class manages the lifecycle and message processing for a single SSH agent session,
         * including session bindings, host information, and protocol message handling.
         *
         * Incoming data is split into frames and complete requests are queued. A single worker
         * thread handles them one by one, so replies are sent in request order (RFC 9987, section 3)
         * and each request gets exactly one reply.
         *
         * For a complete example, see:
         * @see examples/test-agent.cpp
         */
        class Session : virtual public LogEnabler
        {
        public:
            /**
             * @brief Maximum length of a single message, same limit as OpenSSH ssh-agent.
             */
            static constexpr size_t MaxMessageLength = 256 * 1024;

            /**
             * @brief Maximum number of requests waiting for the worker thread.
             */
            static constexpr size_t MaxQueuedRequests = 16;

            /**
             * @brief Constructor for Session.
             */
            Session();

            virtual ~Session();

            /**
             * @brief Confirm a request (e.g., user confirmation).
             * @return true if the request is confirmed, false otherwise.
             */
            virtual bool confirmRequest(const KeyBase &key) = 0;
            /**
             * @brief Process incoming data.
             *
             * Data may contain a part of a message or several messages. Complete messages
             * are queued for the worker thread. Without asynchronous operation the call
             * returns after all queued requests are processed.
             * @param data Pointer to the received data.
             * @param length Length of the received data.
             * @return false if the data violates message framing or the session is stopped,
             *         the caller should close the connection then.
             */
            bool process(const uint8_t *data, size_t length);

            /**
             * @brief Stop processing requests of this session.
             *
             * Queued requests are discarded and new data is rejected. A request that is
             * being processed finishes, see hasPendingOperations().
             */
            void stopProcessing();
            /**
             * @brief Send a message.
             * @param data The message data to be sent.
             * @return true if the message was sent successfully, false otherwise.
             */
            virtual bool send(secure_vector<uint8_t> &data) = 0;

            /**
             * @brief Check if confirmation is required for this session.
             * @return true if confirmation is required, false otherwise.
             */
            virtual bool requiresConfirmation(const KeyBasePtr key) const = 0;

            /**
             * @brief Get the client information for this session.
             * @return The client information.
             */
            virtual std::string client() const = 0;

            /**
             * @brief Process an extension message.
             * @param msg The extension message to process.
             * @return true if the extension message was processed successfully, false otherwise.
             */
            virtual bool processExtensionMessage(const ExtensionMessage &msg)  = 0;

            /**
             * @brief Check if binding attempt failed.
             * @return true if the binding failed, false otherwise.
             */
            bool bindingFailed() const { return m_binding_failed; }

            /**
             * @brief Set the source host for the session.
             *
             * This is currently not used, need to be implemented.
             * @param host The source host.
             */
            void setFromHost(const std::string &host) { m_from_host = host; }

            /**
             * @brief Get the source host for the session.
             *
             * This is currently not used, need to be implemented.
             * @return The source host.
             */
            const std::string &fromHost() const { return m_from_host; }

            /**
             * @brief Set the destination host for the session.
             *
             * This is currently not used, need to be implemented.
             * @param host The destination host.
             */
            void setToHost(const std::string &host) { m_to_host = host; }
            
            /**
             * @brief Get the destination host for the session.
             *
             * This is currently not used, need to be implemented.
             * @return The destination host.
             */
            const std::string &toHost() const { return m_to_host; }

            /**
             * @brief Get the session bindings.
             * @return The session bindings.
             */
            const std::vector<SessionBinding> &sessionBindings() const
            {
                return m_session_bindings;
            }

            /**
             * @brief Get the match information.
             * @return The match information.
             */
            const MatchInfo &matchInfo() const
            {
                return m_match_info;
            }

            /**
             * @brief Send a success response.
             */
            void successResponse();
            /**
             * @brief Send a failure response.
             */
            void failureResponse();
            /**
             * @brief Process a request for identities.
             * @param msg The message containing the request.
             */
            virtual void processRequestIdentities(const Message &msg);

            bool isForwarded() const { return m_is_forwarded; }

            /**
             * @brief Check if the worker thread is still processing a request.
             *
             * While this returns true the worker thread may call virtual methods
             * of this session (send, client, ...), so the session must not be destroyed.
             * @return true if a request is being processed or waits in the queue.
             */
            bool hasPendingOperations() const;

        protected:
            /**
             * @brief Stop the worker thread and wait for it to finish.
             *
             * Derived classes must call this at the beginning of their destructor,
             * before releasing anything used by send(). When ~Session runs, the
             * derived part is already destroyed and a worker thread calling a virtual
             * method would hit a pure virtual call.
             */
            void joinWorkers();

            /**
             * @brief Send the reply to the request being processed.
             *
             * All replies must go through this method, it makes sure that a request
             * gets exactly one reply.
             * @param data The serialized reply.
             * @return true if the reply was sent, false otherwise.
             */
            bool respond(secure_vector<uint8_t> &data);

            std::vector<SessionBinding> m_session_bindings;
            MatchInfo m_match_info;
            bool m_async_operation{true};

        private:
            void processQueue();
            void processRequest(const secure_vector<uint8_t> &request);
            void dispatchRequest(const Message &msg);

            bool processAddIdentity(const Message &msg);
            bool processRemoveIdentity(const Message &msg);
            void processRemoveAllIdentity();
            bool processSignRequest(const Message &msg);
            bool processExtension(const Message &msg);
            bool processLock(const Message &msg);
            bool processUnlock(const Message &msg);

            bool m_binding_failed{false};
            // Host information, used only for information
            // on confirmation request
            std::string m_from_host;
            std::string m_to_host;
            bool m_is_forwarded{false};

            // Used only by the thread calling process()
            secure_vector<uint8_t> m_input_buffer;

            mutable std::mutex m_queue_mutex;
            std::condition_variable m_queue_cv;
            std::deque<secure_vector<uint8_t>> m_requests;
            bool m_processing{false};
            bool m_stopping{false};
            std::thread m_worker;

            // Used only by the worker thread
            bool m_responded{false};
        };
    }
}