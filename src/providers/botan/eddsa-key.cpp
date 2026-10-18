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
#include <libssha/providers/botan/eddsa-key.h>
#include <libssha/providers/botan/eddsa-pub.h>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/base64.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <algorithm>
#include <span>
#include <stdexcept>

namespace nglab
{
    namespace libssha
    {
        std::span<const uint8_t> EDDSABase::secretKey(const secure_vector<uint8_t> &priv_key, size_t key_length)
        {
            if (priv_key.size() != 2 * key_length)
            {
                throw std::runtime_error("EdDSA private key has invalid length");
            }
            return std::span<const uint8_t>(priv_key.data(), key_length);
        }

        void EDDSABase::setPublicKey(const string &type_name, const std::vector<uint8_t> &derived,
                                     const std::vector<uint8_t> &pub_data, const secure_vector<uint8_t> &priv_key)
        {
            // Otherwise the agent would list one key and sign with another
            if (pub_data != derived || !std::equal(derived.begin(), derived.end(), priv_key.end() - derived.size()))
            {
                throw std::runtime_error("EdDSA public key does not match the private key");
            }

            Serializer s;
            s.writeString(type_name);
            s.writeBlob(pub_data);
            m_pub_blob = s.data();
        }

        Ed25519Key::Ed25519Key(const secure_vector<uint8_t> &blob, const std::string &comment)
            : m_priv_key(nullptr)
        {
            setComment(comment);
            Deserializer d(blob);

            vector<uint8_t> pub_data = d.readBlob();
            secure_vector<uint8_t> priv_key = d.readBlobSecure();

            m_priv_key = std::make_unique<Botan::Ed25519_PrivateKey>(
                Botan::Ed25519_PrivateKey::from_seed(secretKey(priv_key, 32)));
            setPublicKey(typeName(), m_priv_key->public_key_bits(), pub_data, priv_key);
            m_pubkey = std::make_unique<ED25519Pub>(m_pub_blob);
        }

        

        std::vector<uint8_t> Ed25519Key::sign(const std::vector<uint8_t> &data, [[maybe_unused]] uint32_t flags) const
        {
            Botan::AutoSeeded_RNG rng;
            Botan::PK_Signer signer(*m_priv_key, rng, "");

            std::vector<uint8_t> signature = signer.sign_message(reinterpret_cast<const uint8_t *>(data.data()), data.size(), rng);
            // Prepare the signature blob as per SSH format

            Serializer s;
            s.writeString(typeName());
            s.writeBlob(signature);

            const auto &blob = s.data();
            return std::vector<uint8_t>(blob.begin(), blob.end());
        }

        Ed448Key::Ed448Key(const secure_vector<uint8_t> &blob, const std::string &comment)
            : m_priv_key()
        {
            setComment(comment);
            Deserializer d(blob);

            std::vector<uint8_t> pub_data = d.readBlob();
            secure_vector<uint8_t> priv_key = d.readBlobSecure();

            m_priv_key = std::make_unique<Botan::Ed448_PrivateKey>(secretKey(priv_key, 57));
            setPublicKey(typeName(), m_priv_key->public_key_bits(), pub_data, priv_key);
            m_pubkey = std::make_unique<ED448Pub>(m_pub_blob);
        }

        std::vector<uint8_t> Ed448Key::sign(const std::vector<uint8_t> &data, [[maybe_unused]] uint32_t flags) const
        {
            Botan::AutoSeeded_RNG rng;
            Botan::PK_Signer signer(*m_priv_key, rng, "");

            std::vector<uint8_t> signature = signer.sign_message(reinterpret_cast<const uint8_t *>(data.data()), data.size(), rng);
            // Prepare the signature blob as per SSH format

            Serializer s;
            s.writeString(typeName());
            s.writeBlob(signature);

            const auto &blob = s.data();
            return std::vector<uint8_t>(blob.begin(), blob.end());
        }

        std::vector<uint8_t> EDDSABase::extractPub(const secure_vector<uint8_t> &data, string type_name)
        {
            Deserializer de(data);
            std::vector<uint8_t> pub_data = de.readBlob();
            
            Serializer se;
            se.writeString(type_name);
            se.writeBlob(pub_data);
            const auto &blob = se.data();
            return std::vector<uint8_t>(blob.begin(), blob.end());
        }

        void EDDSABase::skipBlob(Deserializer &d)
        {
            d.discardBlob(); // skip pubkey
            d.discardBlob(); // skip privkey
        }

        void Ed25519Key::lock(secure_vector<uint8_t>& password)
        {
            protectData(*m_priv_key, password);
            m_priv_key.reset();
        }

        bool Ed25519Key::unlock(secure_vector<uint8_t>& password)
        {            
            auto unprotected = unprotectData(password);
            if(!unprotected)
                return false;

            auto ed25519_key = dynamic_cast<Botan::Ed25519_PrivateKey*>(unprotected.release());
            if(!ed25519_key){
                // Should not happen, but if this occurs, we have a serious problem
                throw std::runtime_error("Unlocked key is not Ed25519_PrivateKey");
            }            

            m_priv_key = std::unique_ptr<Botan::Ed25519_PrivateKey>(ed25519_key);
            return m_priv_key != nullptr;
        }

        void Ed448Key::lock(secure_vector<uint8_t>& password)
        {
            protectData(*m_priv_key, password);
            m_priv_key.reset();
        }


        bool Ed448Key::unlock(secure_vector<uint8_t>& password)
        {
            auto unprotected = unprotectData(password);
            if(!unprotected)
                return false;

            auto ed448_key = dynamic_cast<Botan::Ed448_PrivateKey*>(unprotected.release());
            if(!ed448_key){
                // Should not happen, but if this occurs, we have a serious problem
                throw std::runtime_error("Unlocked key is not Ed448_PrivateKey");
            }

            m_priv_key = std::unique_ptr<Botan::Ed448_PrivateKey>(ed448_key);
            return m_priv_key != nullptr;
        }

    } // namespace libssha
} // namespace nglab
