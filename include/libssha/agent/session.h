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
         * For a complete example, see:
         * @see examples/test-agent.cpp
         */
        class Session : virtual public LogEnabler
        {
        public:
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
             * @brief Process an incoming message.
             * @param data Pointer to the raw message data.
             * @param length Length of the raw message data.
             * @return true if the message was processed successfully, false otherwise.
             */
            bool process(const uint8_t *data, size_t length);
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

        protected:

            std::vector<SessionBinding> m_session_bindings;
            MatchInfo m_match_info;
            bool m_async_operation{true};

        private:
            // Message processing methods
            bool processReal(const uint8_t *data, size_t length);

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
            secure_vector<uint8_t> m_temp_buffer;
            bool m_waiting_for_confirmation{false};
            bool m_waiting_for_key_selection{false};
            std::thread m_confirmation_thread;
            std::thread m_key_selection_thread;
            bool m_is_forwarded{false};
        };
    }
}