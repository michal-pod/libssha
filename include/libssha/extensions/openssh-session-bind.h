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
#include <libssha/extensions/extension.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <memory>
#include <string>
#include <libssha/utils/logger.h>

namespace nglab
{
    namespace libssha
    {
        namespace
        {
            constexpr const char openssh_session_bind_ext_name[] = "session-bind@openssh.com";
        }

        /**
         * @brief This class parses and serializes the OpenSSH session-bind extension.
         *
         * In the SSH agent protocol, the "session-bind@openssh.com" extension is used
         * to bind a specific SSH session to a particular authentication agent.         
         */
        class OpenSSHSessionBind : public Extension<OpenSSHSessionBind,
                                                    openssh_session_bind_ext_name,
                                                    ExtensionType::MessageExtension>,
                                   public LogEnabler
        {
        public:
        /**
         * @brief Construct a new OpenSSHSessionBind object
         */
            OpenSSHSessionBind();

            /**
             * @brief Serialize the extension data to the serializer
             * @param s The serializer to write to
             */
            virtual void serialize(Serializer &s) const override;
            /**
             * @brief Deserialize the extension data from the deserializer
             * @param d The deserializer to read from
             */
            virtual void deserialize(Deserializer &d) override;

            /**
             * @brief Get the Host Key object
             */
            std::vector<uint8_t> hostKey() const { return m_host_key; }

            /**
             * @brief Set the Host Key object
             */
            void setHostKey(const std::vector<uint8_t> &key) { m_host_key = key; }

            /**
             * @brief Get the Session ID
             */
            std::vector<uint8_t> sessionID() const { return m_session_id; }

            /**
             * @brief Set the Session ID
             */
            void setSessionID(const std::vector<uint8_t> &id) { m_session_id = id; }

            /**
             * @brief Get the Signature
             */
            std::vector<uint8_t> signature() const { return m_signature; }

            /**
             * @brief Set the Signature
             */
            void setSignature(const std::vector<uint8_t> &sig) { m_signature = sig; }

            /**
             * @brief Get whether the session is forwarded
             */
            bool forwarded() const { return m_forwarded; }
            
            /**
             * @brief Set whether the session is forwarded
             */
            void setForwarded(bool fwd) { m_forwarded = fwd; }

        private:
            std::vector<uint8_t> m_host_key;
            std::vector<uint8_t> m_session_id;
            std::vector<uint8_t> m_signature;
            bool m_forwarded;
        };
    }
}