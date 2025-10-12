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
#include <string>
#include <libssha/utils/secure_vector.h>
#include <libssha/utils/logger.h>
#include <vector>
#include "message.h"

namespace nglab
{
    namespace libssha
    {
        using std::string;
        using std::vector;

        enum SignRequestFlags : uint32_t
        {
            SSH_AGENT_RSA_SHA2_256 = 2,
            SSH_AGENT_RSA_SHA2_512 = 4,
        };

        /**
         * @brief Class representing a Sign Request Message.
         */
        class SignRequestMessage : public Message, public LogEnabler
        {
        public:
            /**
             * @brief Construct a new Sign Request Message object from a generic Message
             * @param msg The generic Message object
             * @throws std::runtime_error if the message type is incorrect or data is missing
             */
            SignRequestMessage(const Message &msg);
            /**
             * @brief Construct a new empty Sign Request Message object
             */
            SignRequestMessage();
            /**
             * @brief Serialize the message to a binary format
             * @return secure_vector<uint8_t> The serialized message
             * @throws std::runtime_error if the message type is incorrect
             */
            virtual secure_vector<uint8_t> serialize() const override;


            /**
             * @brief Get the key blob
             * @return const vector<uint8_t>& The key blob
             */
            const vector<uint8_t> &keyBlob() const { return m_key_blob; }
            /**
             * @brief Set the key blob
             * @param key_blob The key blob to set
             */
            void setKeyBlob(const vector<uint8_t> &key_blob) { m_key_blob = key_blob; }
            /**
             * @brief Get the data
             * @return const vector<uint8_t>& The data
             */
            const vector<uint8_t> &data() const { return m_data_sign; }
            /**
             * @brief Set the data
             * @param data The data to set
             */
            void setData(const vector<uint8_t> &data) { m_data_sign = data; }
            /**
             * @brief Get the flags
             * @return uint32_t The flags
             */
            uint32_t flags() const { return m_flags; }
            /**
             * @brief Set the flags
             * @param flags The flags to set
             */
            void setFlags(uint32_t flags) { m_flags = flags; }

        private:
            /**
             * @brief Deserialize the message from raw data
             * @param data The raw data to deserialize from
             * @throws std::runtime_error if the message type is incorrect
             * @throws std::out_of_range if the data is malformed or incomplete
             */
            virtual void deserialize(Deserializer &d) override;

            vector<uint8_t> m_key_blob;
            vector<uint8_t> m_data_sign;
            uint32_t m_flags; // reserved for future use
        };
    }
}