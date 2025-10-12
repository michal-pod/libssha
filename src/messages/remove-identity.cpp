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
#include <libssha/messages/remove-identity.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <stdexcept>

namespace nglab
{
    namespace libssha
    {
        RemoveIdentityMessage::RemoveIdentityMessage()
            : Message(SSH_AGENTC_REMOVE_IDENTITY)
        {}

        RemoveIdentityMessage::RemoveIdentityMessage(const Message &msg)
            : Message()
        {
            if (msg.type() != SSH_AGENTC_REMOVE_IDENTITY)
            {
                throw std::runtime_error("RemoveIdentityMessage: incorrect message type");
            }
            if (msg.data() == nullptr || msg.length() == 0)
            {
                throw std::runtime_error("RemoveIdentityMessage: no data");
            }

            Deserializer d(msg.data(), msg.length());
            deserialize(d);
        }

        secure_vector<uint8_t> RemoveIdentityMessage::serialize() const
        {
            Serializer s;
            Message::serialize(s);
            s.writeBlob(m_key_blob);
            s.finalize();
            return s.dataSecure();
        }

        const std::vector<uint8_t> &RemoveIdentityMessage::keyBlob() const
        {
            return m_key_blob;
        }

        void RemoveIdentityMessage::setKeyBlob(const std::vector<uint8_t> &key_blob)
        {
            m_key_blob = key_blob;
        }

        void RemoveIdentityMessage::deserialize(Deserializer &d)
        {
            Message::deserialize(d);
            if (m_type != SSH_AGENTC_REMOVE_IDENTITY)
            {
                throw std::runtime_error("RemoveIdentityMessage: incorrect message type");
            }
            m_key_blob = d.readBlob();
        }
    }
}
