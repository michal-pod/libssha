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
#include <libssha/providers/botan/rsa-key.h>
#include <libssha/providers/botan/rsa-pub.h>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/base64.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <stdexcept>
#include <libssha/messages/sign-request.h>

namespace nglab
{
    namespace libssha
    {

        RsaKey::RsaKey(const secure_vector<uint8_t> &blob, const std::string &comment)
            : m_priv_key()
        {
            setComment(comment);
            Deserializer de(blob);
            auto n = de.readMPInt();       // n
            auto e = de.readMPInt();       // e
            auto d = de.readMPIntSecure(); // d
            de.discardBlob();             // iqmp
            auto p = de.readMPIntSecure(); // p
            auto q = de.readMPIntSecure(); // q

            auto n_bi = Botan::BigInt(vector<uint8_t>(n.begin(), n.end()));
            auto e_bi = Botan::BigInt(vector<uint8_t>(e.begin(), e.end()));
            auto d_bi = Botan::BigInt(Botan::secure_vector<uint8_t>(d.begin(), d.end()));
            auto p_bi = Botan::BigInt(Botan::secure_vector<uint8_t>(p.begin(), p.end()));
            auto q_bi = Botan::BigInt(Botan::secure_vector<uint8_t>(q.begin(), q.end()));

            m_priv_key = std::make_unique<Botan::RSA_PrivateKey>(
                p_bi,
                q_bi,
                e_bi,
                d_bi,
                n_bi);

            Serializer s;
            s.writeString("ssh-rsa");
            s.writeMPInt(e);
            s.writeMPInt(n);
            const auto &secure_data = s.data();
            m_pubkey = std::make_unique<RSAPub>(std::vector<uint8_t>(secure_data.begin(), secure_data.end()));
            m_pub_blob = std::vector<unsigned char>(secure_data.begin(), secure_data.end());
        }

        std::vector<uint8_t> RsaKey::extractPub(const secure_vector<uint8_t> &data)
        {
            Deserializer de(data);
            auto n = de.readMPInt();
            auto e = de.readMPInt();

            Serializer se;
            se.writeString("ssh-rsa");
            se.writeMPInt(e);
            se.writeMPInt(n);
            const auto &blob = se.data();
            return std::vector<uint8_t>(blob.begin(), blob.end());
        }

        std::vector<uint8_t> RsaKey::sign(const std::vector<uint8_t> &data, uint32_t flags) const
        {
            Botan::AutoSeeded_RNG rng;
            string algoritm = "EMSA-PKCS1-v1_5(SHA-1)";
            string response_type = "ssh-rsa";
            if(flags & SignRequestFlags::SSH_AGENT_RSA_SHA2_512)
            {
                algoritm = "EMSA-PKCS1-v1_5(SHA-512)";
                response_type = "rsa-sha2-512";
            }
            else if(flags & SignRequestFlags::SSH_AGENT_RSA_SHA2_256)
            {
                algoritm = "EMSA-PKCS1-v1_5(SHA-256)";
                response_type = "rsa-sha2-256";
            }

            Botan::PK_Signer signer(*m_priv_key, rng, algoritm);
            auto signature = signer.sign_message(
                reinterpret_cast<const uint8_t *>(data.data()), data.size(), rng);

            Serializer s;
            s.writeString(response_type);
            s.writeBlob(signature);

            const auto &blob = s.data();

            return std::vector<uint8_t>(blob.begin(), blob.end());
        }

        void RsaKey::skipBlob(Deserializer &d)
        {
            d.discardBlob(); // skip n
            d.discardBlob(); // skip e
            d.discardBlob(); // skip d
            d.discardBlob(); // skip iqmp
            d.discardBlob(); // skip p
            d.discardBlob(); // skip q
        }

        void RsaKey::lock(secure_vector<uint8_t>& password)
        {
            protectData(*m_priv_key, password);
            m_priv_key.reset();
        }

        bool RsaKey::unlock(secure_vector<uint8_t>& password)
        {
            auto unprotected = unprotectData(password);
            if(!unprotected)
                return false;

            auto rsa_key = dynamic_cast<Botan::RSA_PrivateKey*>(unprotected.release());
            if(!rsa_key){
                // Should not happen, but if this occurs, we have a serious problem
                throw std::runtime_error("Unlocked key is not RSA_PrivateKey");
            }

            m_priv_key = std::unique_ptr<Botan::RSA_PrivateKey>(rsa_key);
            return m_priv_key != nullptr;
        }

    } // namespace libssha
} // namespace nglab
