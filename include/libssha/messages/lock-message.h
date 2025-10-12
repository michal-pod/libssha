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
         * @brief Class template representing a Lock/Unlock Message.
         */
        template <uint8_t msg_type>
        class LockMessageBase : public Message
        {
        public:
            LockMessageBase();
            LockMessageBase(const Message &msg);
            /**
             * Serialize the LockMessage to a string.
             * @return A string containing the serialized message.
             */
            virtual secure_vector<uint8_t> serialize() const override;

            /**
             * Get the password used for locking/unlocking.
             * @return A secure vector containing the password.
             */
            const secure_vector<uint8_t> &password() const;
            
            /**
             * Set the password used for locking/unlocking.
             * @param password A secure vector containing the password.
             */
            void setPassword(const secure_vector<uint8_t> &password);

        private:
            /**
             * Deserialize the LockMessage from a string.
             * @param data The string containing the serialized message.
             */
            virtual void deserialize(Deserializer &d) override;
            nglab::libssha::secure_vector<uint8_t> m_password;
        };

        /**
         * @brief Type alias for LockMessage and UnlockMessage.
         */
        typedef LockMessageBase<SSH_AGENTC_LOCK> LockMessage;
        /**
         * @brief Type alias for UnlockMessage.
         */
        typedef LockMessageBase<SSH_AGENTC_UNLOCK> UnlockMessage;
    }
}