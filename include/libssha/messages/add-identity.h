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
#include "message.h"
#include <string>
#include <vector>
#include <memory>
#include <libssha/utils/secure_vector.h>
#include <libssha/utils/logger.h>

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;
        class ExtensionBase;

        /**
         * @brief Class representing an Add Identity Message.
         */
        class AddIdentityMessage : public Message, public LogEnabler
        {
        public:
        /**
         * @brief Construct a new Add Identity Message object
         */
            AddIdentityMessage();

            /**
             * @brief Construct a new Add Identity Message object from a generic Message
             * @param msg The generic Message object
             * @throws std::runtime_error if the message type is incorrect or data is missing
             */
            AddIdentityMessage(const Message &msg);

            /**
             * @brief Serialize the message to a binary format
             * @return secure_vector<uint8_t> The serialized message
             * @throws std::runtime_error if the message type is incorrect
             */
            virtual secure_vector<uint8_t> serialize() const override;

            /**
             * @brief Get the key type
             * @return const string& The key type
             */
            const string &keyType() const { return m_key_type; }

            /**
             * @brief Set the key type
             * @param key_type The key type to set
             */
            void setKeyType(const string &key_type) { m_key_type = key_type; }

            /**
             * @brief Get the key comment
             * @return const string& The key comment
             */
            const string &keyComment() const { return m_key_comment; }

            /**
             * @brief Set the key comment
             * @param key_comment The key comment to set
             */
            void setKeyComment(const string &key_comment) { m_key_comment = key_comment; }

            /**
             * @brief Get the key blob
             * @return const secure_vector<uint8_t>& The key blob
             */
            const secure_vector<uint8_t> &keyBlob() const { return m_key_blob; }

            /**
             * @brief Set the key blob
             * @param key_blob The key blob to set
             */
            void setKeyBlob(const secure_vector<uint8_t> &key_blob) { m_key_blob = key_blob; }

            /**
             * @brief Get the confirm required flag
             * @return true if confirmation is required, false otherwise
             */
            bool confirmRequired() const { return m_confirm_required; }

            /**
             * @brief Set the confirm required flag
             * @param confirm_required true to require confirmation, false otherwise
             */
            void setConfirmRequired(bool confirm_required)
            {
                m_type = SSH_AGENTC_ADD_IDENTITY_CONSTRAINED;
                m_confirm_required = confirm_required;
            }

            /**
             * @brief Get the lifetime in seconds
             * @return uint32_t The lifetime in seconds
             */
            uint32_t lifetime() const { return m_lifetime; }

            /**
             * @brief Set the lifetime in seconds
             * @param lifetime The lifetime in seconds
             */
            void setLifetime(uint32_t lifetime)
            {
                m_type = SSH_AGENTC_ADD_IDENTITY_CONSTRAINED;
                m_lifetime = lifetime;
            }

            /**
             * @brief Get the extension constraint
             * @return const std::shared_ptr<ExtensionBase> & The extension constraint
             */
            const std::shared_ptr<ExtensionBase> &extension() const { return m_extension; }

            /**
             * @brief Set the extension constraint
             * @param extension The extension constraint
             */
            void setExtension(const std::shared_ptr<ExtensionBase> &extension) { m_extension = extension; }

        private:
            virtual void deserialize(Deserializer &s) override;

            string m_key_type;
            secure_vector<uint8_t> m_key_blob;
            string m_key_comment;
            bool m_confirm_required;
            uint32_t m_lifetime; // seconds
            std::shared_ptr<ExtensionBase> m_extension;
        };
    }
}