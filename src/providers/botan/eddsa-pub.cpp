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
#include <libssha/providers/botan/eddsa-pub.h>
#include <libssha/utils/deserializer.h>
#include <botan/hash.h>
#include <botan/base64.h>
#include <botan/pubkey.h>
namespace nglab
{
    namespace libssha
    {

        ED25519Pub::ED25519Pub(const std::vector<uint8_t> &blob) : PubKey(blob)
        {
            Deserializer d(blob);
            m_type = d.readString();
            if (m_type != typeName())
            {
                throw std::runtime_error("ED25519Pub: invalid key type: " + m_type);
            }
            auto pubkey_blob = d.readMPInt();

            m_pub_key = std::make_unique<Botan::Ed25519_PublicKey>(pubkey_blob);
        }

        bool ED25519Pub::verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const
        {
            Deserializer d(signature);
            std::string sig_type = d.readString();
            if (sig_type != typeName())
            {
                throw std::runtime_error("ED25519Pub: invalid signature type: " + sig_type);
            }
            std::string sig_blob = d.readString();

            Botan::PK_Verifier verifier(*m_pub_key, "");
            return verifier.verify_message(
                reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                reinterpret_cast<const uint8_t *>(sig_blob.data()), sig_blob.size());
        }

        size_t ED25519Pub::bits() const
        {
            return m_pub_key->key_length();
        }

        ED448Pub::ED448Pub(const std::vector<uint8_t> &blob) : PubKey(blob)
        {
            Deserializer d(blob);
            m_type = d.readString();
            if (m_type != ED448Pub::typeName())
            {
                throw std::runtime_error("ED448Pub: invalid key type: " + m_type);
            }
            auto pubkey_blob = d.readMPInt();

            m_pub_key = std::make_unique<Botan::Ed448_PublicKey>(pubkey_blob);
        }

        bool ED448Pub::verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const
        {
            Deserializer d(signature);
            std::string sig_type = d.readString();
            if (sig_type != typeName())
            {
                throw std::runtime_error("ED448Pub: invalid signature type: " + sig_type);
            }
            std::string sig_blob = d.readString();

            Botan::PK_Verifier verifier(*m_pub_key, "");
            return verifier.verify_message(
                reinterpret_cast<const uint8_t *>(data.data()), data.size(),
                reinterpret_cast<const uint8_t *>(sig_blob.data()), sig_blob.size());
        }

        size_t ED448Pub::bits() const
        {
            return m_pub_key->key_length();
        }

    }
}