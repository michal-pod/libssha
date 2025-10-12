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
#include "message.h"

namespace nglab
{
    namespace libssha
    {
        using std::string;
        /**
         * @brief Class representing a Sign Response Message.
         */
        class SignResponseMessage : public Message
        {
        public:
            /**
             * @brief Constructs a SignResponseMessage with the given signature data.
             * @param data The signature data to be included in the message.
             */
            SignResponseMessage(const Message &msg);
            /**
             * @brief Default constructor for SignResponseMessage.
             * @note Initializes the message type to SIGN_RESPONSE and leaves the signature empty.
             */
            SignResponseMessage();
            /**
             * @brief Serialize the message to a binary format
             * @return secure_vector<uint8_t> The serialized message
             * @throws std::runtime_error if the message type is incorrect
             */
            virtual secure_vector<uint8_t> serialize() const override;

            /**
             * @brief Get the signature
             * @return const std::vector<uint8_t>& The signature
             */
            const std::vector<uint8_t> &signature() const { return m_signature; }
            /**
             * @brief Set the signature
             * @param sig The signature to set
             */
            void setSignature(const std::vector<uint8_t> &sig) { m_signature = sig; }

        private:
            /**
             * @brief Deserialize the message from raw data
             * @param data The raw data to deserialize from
             * @throws std::runtime_error if the message type is incorrect
             * @throws std::out_of_range if the data is malformed or incomplete
             */
            virtual void deserialize(Deserializer &d) override;
            std::vector<uint8_t> m_signature;
        };
    }
}