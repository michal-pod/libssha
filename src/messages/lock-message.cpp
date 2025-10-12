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
#include <libssha/messages/lock-message.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <stdexcept>

namespace nglab
{
    namespace libssha
    {
        template <uint8_t msg_type>
        LockMessageBase<msg_type>::LockMessageBase()
            : Message(msg_type)
        {}

        template <uint8_t msg_type>
        LockMessageBase<msg_type>::LockMessageBase(const Message &msg)
            : Message()
        {
            if (msg.type() != msg_type)
            {
                throw std::runtime_error("LockMessage: incorrect message type");
            }
            if (msg.data() == nullptr || msg.length() == 0)
            {
                throw std::runtime_error("LockMessage: no data");
            }

            Deserializer d(msg.data(), msg.length());
            deserialize(d);
        }

        template <uint8_t msg_type>
        secure_vector<uint8_t> LockMessageBase<msg_type>::serialize() const
        {
            Serializer s;
            Message::serialize(s);
            s.writeSecureBlob(m_password);
            s.finalize();
            return s.dataSecure();
        }

        template <uint8_t msg_type>
        const secure_vector<uint8_t> &LockMessageBase<msg_type>::password() const
        {
            return m_password;
        }

        template <uint8_t msg_type>
        void LockMessageBase<msg_type>::setPassword(const secure_vector<uint8_t> &password)
        {
            m_password = password;
        }

        template <uint8_t msg_type>
        void LockMessageBase<msg_type>::deserialize(Deserializer &d)
        {
            Message::deserialize(d);

            if (m_type != msg_type)
                throw std::runtime_error("LockMessage: incorrect message type");

            m_password = d.readBlobSecure();
        }

        // Explicit template instantiation for required types
        template class LockMessageBase<SSH_AGENTC_LOCK>;
        template class LockMessageBase<SSH_AGENTC_UNLOCK>;
    }
}
