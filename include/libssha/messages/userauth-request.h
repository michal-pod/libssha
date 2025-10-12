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
#include <vector>
#include <cstdint>
#include <string>
#include <libssha/utils/logger.h>

namespace nglab
{
    namespace libssha
    {
        /**
         * @brief Class representing a User Authentication Request Message.
         *
         * This class parses and provides access to the fields of a user authentication
         * request message as used in the SSH agent protocol.
         *
         * Typical usage:
         * @code
         * // See: examples/test-agent.cpp for a full usage example.
         * std::vector<uint8_t> raw_data = ...; // obtain from network or test
         * UserAuthRequestMessage msg(raw_data);
         * std::string user = msg.username();
         * std::string key_type = msg.keyType();
         * const std::vector<uint8_t>& pubkey = msg.publicKey();
         * @endcode
         *
         * For a complete example, see:
         * @see /home/michal/src/libssha/examples/test-agent.cpp
         */
        class UserAuthRequestMessage : public LogEnabler
        {
        public:
            /**
             * @brief Construct a new UserAuthRequestMessage object from raw data.
             * @param data The raw message data.
             * @throws std::runtime_error if the message is invalid or unsupported.
             */
            UserAuthRequestMessage(const std::vector<uint8_t> &data);

            /**
             * @brief Get the session ID.
             * @return std::vector<uint8_t> The session ID.
             */
            std::vector<uint8_t> sessionId() const { return m_session_id; }

            /**
             * @brief Get the username.
             * @return std::string The username.
             */
            std::string username() const { return m_username; }

            /**
             * @brief Get the key type.
             * @return std::string The key type.
             */
            std::string keyType() const { return m_key_type; }

            /**
             * @brief Get the public key.
             * @return const std::vector<uint8_t>& The public key.
             */
            const std::vector<uint8_t>& publicKey() const { return m_public_key; }

            /**
             * @brief Get the server host key.
             * @return const std::vector<uint8_t>& The server host key.
             */
            const std::vector<uint8_t>& serverHostKey() const { return m_server_host_key; }

        private:
            std::vector<uint8_t> m_session_id; ///< The session ID.
            std::string m_username; ///< The username.
            std::string m_key_type; ///< The key type.
            std::vector<uint8_t> m_public_key; ///< The public key.
            std::vector<uint8_t> m_server_host_key; ///< The server host key.
            const uint8_t SSH_MSG_USERAUTH_REQUEST = 50; ///< SSH message type for user authentication request.
        };
    }
}