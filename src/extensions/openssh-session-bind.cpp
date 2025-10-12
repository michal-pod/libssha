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
#include <libssha/extensions/openssh-session-bind.h>
#include <libssha/key/key-factory.h>
#include <libssha/key/pub-key.h>

namespace nglab
{
    namespace libssha
    {

        OpenSSHSessionBind::OpenSSHSessionBind() : LogEnabler("OpenSSHSessionBind")
        {
            log.vdebug("extension created");
        }

        void OpenSSHSessionBind::serialize(Serializer &s) const
        {
            log.vdebug("serializing");
            s.writeBlob(m_host_key);
            s.writeBlob(m_session_id);
            s.writeBlob(m_signature);
            s.writeByte(m_forwarded ? 1 : 0);            
        }

        void OpenSSHSessionBind::deserialize(Deserializer &d)
        {
            log.vdebug("deserializing");
            m_host_key = d.readBlob();
            m_session_id = d.readBlob();
            m_signature = d.readBlob();
            m_forwarded = d.readByte() != 0;
            log.debug("Host key size: {}, Session ID size: {}, Signature size: {}, Forwarded: {}",
                    m_host_key.size(), m_session_id.size(), m_signature.size(), m_forwarded);

            // FIXME: move deserialization to PubKeyBase derived class
            Deserializer d_hk(m_host_key);            
            std::string key_type = d_hk.readString();
            auto blob_key = d_hk.readBlob();
            auto pubkey = KeyFactory::createPubKey(key_type, m_host_key);

            log.vdebug("Host key type: {}, fingerprint: {}", key_type, pubkey->fingerprint());
            
            if(m_signature.size() > 0) {
                Deserializer d_sig(m_signature);
                std::string sig_type = d_sig.readString();
                auto sig_blob = d_sig.readBlob();
                log.vdebug("Signature type: {}, Signature size: {}", sig_type, sig_blob.size());

                if(!pubkey->verify(m_session_id, m_signature)){
                    log.error("Signature verification failed!");
                    throw std::runtime_error("OpenSSHSessionBind: signature verification failed");
                }
                else {
                    log.debug("Signature verification succeeded.");
                }
            }
        }

    } // namespace libssha
} // namespace nglab