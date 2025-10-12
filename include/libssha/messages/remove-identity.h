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
         * @brief Class representing a Remove Identity Message.
         */
        class RemoveIdentityMessage : public Message
        {
        public:
            /**
             * @brief Construct a new Remove Identity Message object
             */
            RemoveIdentityMessage();

            /**
             * @brief Construct a new Remove Identity Message object from a generic Message
             * @param msg The generic Message object
             * @throws std::runtime_error if the message type is incorrect or data is missing
             */
            RemoveIdentityMessage(const Message &msg);

            /**
             * @brief Serialize the message to a binary format
             * @return secure_vector<uint8_t> The serialized message
             * @throws std::runtime_error if the message type is incorrect
             */
            virtual secure_vector<uint8_t> serialize() const override;

            /**
             * @brief Get the key blob
             * @return const std::vector<uint8_t>& The key blob
             */
            const std::vector<uint8_t> &keyBlob() const;

            /**
             * @brief Set the key blob
             * @param key_blob The key blob to set
             */
            void setKeyBlob(const std::vector<uint8_t> &key_blob);

        private:
            virtual void deserialize(Deserializer &d) override;
            std::vector<uint8_t> m_key_blob;
        };
    }
}