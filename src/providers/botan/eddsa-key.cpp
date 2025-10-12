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
#include <stdexcept>

namespace nglab
{
    namespace libssha
    {

        Ed25519Key::Ed25519Key(const secure_vector<uint8_t> &blob, const std::string &comment)
            : m_priv_key()
        {
            setComment(comment);
            Deserializer d(blob);

            vector<uint8_t> pub_data = d.readBlob();
            secure_vector<uint8_t> priv_key = d.readBlobSecure();

            m_priv_key = std::make_unique<Botan::Ed25519_PrivateKey>(Botan::secure_vector<uint8_t>(priv_key.begin(), priv_key.end()));

            Serializer s;
            //s.writeBE32(0); // Temporary placeholder for the public key length
            s.writeString(typeName());
            s.writeBlob(pub_data);
            //s.writeBE32(s.size()-4, 0);
            const auto &secure_data = s.data();

            m_pubkey = std::make_unique<ED25519Pub>(std::vector<uint8_t>(secure_data.begin(), secure_data.end()));
            m_pub_blob = std::vector<unsigned char>(secure_data.begin(), secure_data.end());
        }

        

        std::vector<uint8_t> Ed25519Key::sign(const std::vector<uint8_t> &data, uint32_t flags) const
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

            m_priv_key = std::make_unique<Botan::Ed448_PrivateKey>(priv_key);

            Serializer s;
            //s.writeBE32(0); // Temporary placeholder for the public key length
            s.writeString(typeName());
            s.writeBlob(pub_data);
            //s.writeBE32(s.size()-4, 0);
            const auto &secure_data = s.data();

            m_pubkey = std::make_unique<ED448Pub>(std::vector<uint8_t>(secure_data.begin(), secure_data.end()));
            m_pub_blob = std::vector<unsigned char>(secure_data.begin(), secure_data.end());
        }

        std::vector<uint8_t> Ed448Key::sign(const std::vector<uint8_t> &data, uint32_t flags) const
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

        string EDDSABase::fingerprint() const
        {
            // Compute SHA256 hash of the public key blob
            const auto sha256 = Botan::HashFunction::create_or_throw("SHA-256");
            sha256->update(m_pub_blob);
            auto digest = sha256->final();

            // Encode the hash in base64
            std::string b64 = Botan::base64_encode(digest);
            
            while (!b64.empty() && b64.back() == '=') {
                b64.pop_back();
            }

            return "SHA256:" + b64;
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
