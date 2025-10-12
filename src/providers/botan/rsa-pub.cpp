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
#include <libssha/providers/botan/rsa-pub.h>
#include <botan/pubkey.h>

namespace nglab
{
    namespace libssha
    {

        RSAPub::RSAPub(const std::vector<uint8_t> &blob) : PubKey(blob)
        {
            
            Deserializer d(blob);
            m_type = d.readString();

            auto e = d.readMPInt();
            auto n = d.readMPInt();

            auto n_bi = Botan::BigInt(n);
            auto e_bi = Botan::BigInt(e);

            m_pub_key = std::make_unique<Botan::RSA_PublicKey>(n_bi, e_bi);
        }

        bool RSAPub::verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const        
        {
            Deserializer d(signature);
            std::string sig_type = d.readString();

            std::string algoritm;
            if(sig_type == "rsa-sha2-512")
            {
                algoritm = "EMSA-PKCS1-v1_5(SHA-512)";
            }
            else if(sig_type == "rsa-sha2-256")
            {
                algoritm = "EMSA-PKCS1-v1_5(SHA-256)";
            }
            else if(sig_type == "ssh-rsa")
            {
                algoritm = "EMSA-PKCS1-v1_5(SHA-1)";
            }
            else
            {
                throw std::runtime_error("RSAPub: invalid signature type: " + sig_type);
            }
            
            auto sig_blob = d.readBlob();

            Botan::PK_Verifier verifier(*m_pub_key, algoritm);
            return verifier.verify_message(
                reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                reinterpret_cast<const uint8_t *>(sig_blob.data()), sig_blob.size());
        }

        size_t RSAPub::bits() const
        {
            return m_pub_key->key_length();
        }

    } // namespace libssha
} // namespace nglab