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
#include <libssha/messages/identities-answer.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <stdexcept>

namespace nglab
{
    namespace libssha
    {
        IdentitiesAnswerMessage::IdentitiesAnswerMessage()
            : Message(SSH_AGENT_IDENTITIES_ANSWER)
        {
        }

        IdentitiesAnswerMessage::IdentitiesAnswerMessage(const Message &msg)
            : Message()
        {
            if (msg.type() != SSH_AGENT_IDENTITIES_ANSWER)
            {
                throw std::runtime_error("IdentitiesAnswerMessage: incorrect message type");
            }
            if (msg.data() == nullptr || msg.length() == 0)
            {
                throw std::runtime_error("AddIdentityMessage: no data");
            }

            Deserializer d(msg.data(), msg.length());
            deserialize(d);
        }

        secure_vector<uint8_t> IdentitiesAnswerMessage::serialize() const
        {
            Serializer s;
            Message::serialize(s);
            s.writeBE32(static_cast<uint32_t>(m_identities.size()));
            for (const auto &id : m_identities)
            {
                s.writeBlob(id.blob());
                s.writeString(id.comment());
            }
            s.finalize();
            return s.dataSecure();
        }

        void IdentitiesAnswerMessage::deserialize(Deserializer &d)
        {
            Message::deserialize(d);
            
            if (m_type != SSH_AGENT_IDENTITIES_ANSWER)
                throw std::runtime_error("IdentitiesAnswerMessage: incorrect message type");
            
            if( d.remaining() < 4 )
                throw std::out_of_range("IdentitiesAnswerMessage: not enough data for count");
                
            uint32_t count = d.readBE32();
            m_identities.clear();
            for (uint32_t i = 0; i < count; ++i)
            {
                auto blob = d.readBlob();
                auto comment = d.readString();
                m_identities.emplace_back(blob, comment);
            }
        }

    } // namespace libssha
} // namespace nglab
