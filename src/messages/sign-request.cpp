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
#include <libssha/messages/sign-request.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <stdexcept>

namespace nglab
{
    namespace libssha
    {

        SignRequestMessage::SignRequestMessage()
            : Message(SSH_AGENTC_SIGN_REQUEST), LogEnabler("SignRequestMessage"), m_flags(0)
        {
        }

        SignRequestMessage::SignRequestMessage(const Message &msg)
            : Message(), LogEnabler("SignRequestMessage")
        {
            if (msg.type() != SSH_AGENTC_SIGN_REQUEST)
            {
                log.error("incorrect message type");
                throw std::runtime_error("SignRequestMessage: incorrect message type");
            }

            if (msg.data() == nullptr || msg.length() == 0)
            {
                log.error("no data");
                throw std::runtime_error("SignRequestMessage: no data");
            }

            Deserializer d(msg.data(), msg.length());
            deserialize(d);
        }

        secure_vector<uint8_t> SignRequestMessage::serialize() const
        {
            Serializer s;
            Message::serialize(s);
            s.writeBlob(m_key_blob);
            s.writeBlob(m_data_sign);
            s.writeBE32(m_flags);
            s.finalize();
            return s.dataSecure();
        }

        void SignRequestMessage::deserialize(Deserializer &d)
        {
            Message::deserialize(d);

            if (m_type != SSH_AGENTC_SIGN_REQUEST){
                log.error("incorrect message type");
                throw std::runtime_error("SignRequestMessage: incorrect message type");
            }
            m_key_blob = d.readBlob();
            m_data_sign = d.readBlob();
            m_flags = d.readBE32();            
        }

    } // namespace libssha
} // namespace nglab
