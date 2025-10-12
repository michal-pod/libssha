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
#include <libssha/utils/deserializer.h>
#include <libssha/messages/userauth-request.h>
namespace nglab
{
    namespace libssha
    {
        UserAuthRequestMessage::UserAuthRequestMessage(const std::vector<uint8_t> &data) : LogEnabler("UserAuthRequestMessage")
        {
            Deserializer d(data);
            m_session_id = d.readBlob();

            if(m_session_id.size() == 0)
            {
                log.error("empty session ID");
                throw std::runtime_error("UserAuthRequestMessage: empty session ID");
            }            

            auto msg_type = d.readByte();
            if (msg_type != SSH_MSG_USERAUTH_REQUEST)
            {
                log.error("incorrect message type: {}", msg_type);
                throw std::runtime_error("UserAuthRequestMessage: incorrect message type");
            }
            m_username = d.readString();

                       
            auto service_name = d.readString();            
            auto method_name = d.readString();            
            bool has_signature = d.readByte() != 0;
            if(service_name != "ssh-connection" || method_name != "publickey-hostbound-v00@openssh.com" || !has_signature)
            {
                log.error("unsupported service/method/signature: {}/{}/{}", service_name, method_name, has_signature);
                throw std::runtime_error("UserAuthRequestMessage: unsupported service/method/signature");
            }
            
            m_key_type = d.readString();           
            m_public_key = d.readBlob();            
            m_server_host_key = d.readBlob();            
        }
    } // namespace libssha
} // namespace nglab