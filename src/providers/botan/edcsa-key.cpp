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
#include <libssha/providers/botan/edcsa-key.h>
#include <libssha/providers/botan/edcsa-pub.h>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/base64.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/bigint.h>
#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <stdexcept>
namespace nglab
{
    namespace libssha
    {

        ECDSAKey::ECDSAKey(const secure_vector<uint8_t> &blob, const std::string &comment, const std::string &type_name)
            : m_priv_key(), m_type_name(type_name)
        {
            setComment(comment);
            Deserializer d(blob);

            // string m_type_name = d.readBlob();
            m_curve_name = d.readString();
            vector<uint8_t> pub_data = d.readBlob();
            secure_vector<uint8_t> priv_key = d.readMPIntSecure();

            if (m_curve_name == "nistp256")
            {
                m_botan_curve_name = "secp256r1";
                m_signature_algorithm = "EMSA1(SHA-256)";
                // Ensure private key is 32 bytes
                while(priv_key.size() < 32){
                    priv_key.insert(priv_key.begin(), 1, 0x00);
                }
            }
            else if (m_curve_name == "nistp384")
            {
                m_botan_curve_name = "secp384r1";
                m_signature_algorithm = "EMSA1(SHA-384)";
                // Ensure private key is 48 bytes
                while(priv_key.size() < 48){
                    priv_key.insert(priv_key.begin(), 1, 0x00);
                }
            }
            else if (m_curve_name == "nistp521")
            {
                m_botan_curve_name = "secp521r1";
                // Ensure private key is 66 bytes
                while(priv_key.size() < 66){
                    priv_key.insert(priv_key.begin(), 1, 0x00);
                }
                m_signature_algorithm = "EMSA1(SHA-512)";
            }
            else
            {
                throw std::runtime_error("ECDSABase: unknown curve name: " + m_curve_name);
            }

            const auto domain = Botan::EC_Group::from_name(m_botan_curve_name);
            const auto priv_scalar = Botan::EC_Scalar::deserialize(domain, priv_key);
            if (!priv_scalar)
            {
                throw std::runtime_error("ECDSABase: invalid private scalar");
            }

            m_priv_key = std::make_unique<Botan::ECDSA_PrivateKey>(domain, priv_scalar.value());

            Serializer s;
            s.writeString(m_type_name);
            s.writeString(m_curve_name);
            s.writeBlob(pub_data);
            const auto &secure_data = s.data();

            m_pubkey = std::make_unique<ECDSAPub>(std::vector<uint8_t>(secure_data.begin(), secure_data.end()));
            m_pub_blob = std::vector<unsigned char>(secure_data.begin(), secure_data.end());
        }

        void ECDSAKey::skipBlob(Deserializer &d)
        {
            d.discardBlob(); // curve name
            d.discardBlob(); // pubkey
            d.discardBlob(); // privkey
        }

        std::vector<uint8_t> ECDSAKey::extractPub(const secure_vector<uint8_t> &data)
        {
            Deserializer de(data);
            string curve_name = de.readString();
            vector<uint8_t> pub_data = de.readBlob();

            string type_name;
            if (curve_name == "nistp256")
            {
                type_name = edcsa_sha2_nistp256_type_name;
            }
            else if (curve_name == "nistp384")
            {
                type_name = edcsa_sha2_nistp384_type_name;
            }
            else if (curve_name == "nistp521")
            {
                type_name = edcsa_sha2_nistp521_type_name;
            }
            else
            {
                throw std::runtime_error("ECDSABase::extractPub: unknown curve name: " + curve_name);
            }

            Serializer se;
            se.writeString(type_name);
            se.writeString(curve_name);
            se.writeBlob(pub_data);
            const auto &blob = se.data();
            return std::vector<uint8_t>(blob.begin(), blob.end());
        }

        string ECDSAKey::fingerprint() const
        {
            // Compute SHA256 hash of the public key blob
            const auto sha256 = Botan::HashFunction::create_or_throw("EMSA1(SHA-256)");
            sha256->update(m_pub_blob);
            auto digest = sha256->final();

            // Encode the hash in base64
            std::string b64 = Botan::base64_encode(digest);
            
            while (!b64.empty() && b64.back() == '=') {
                b64.pop_back();
            }

            return "SHA256:" + b64;
        }

        std::vector<uint8_t> ECDSAKey::sign(const std::vector<uint8_t> &data, [[maybe_unused]] uint32_t flags) const
        {
            Botan::AutoSeeded_RNG rng;
            Botan::PK_Signer signer(*m_priv_key, rng, m_signature_algorithm, Botan::Signature_Format::DerSequence);

            std::vector<uint8_t> signature = signer.sign_message(data.data(), data.size(), rng);

            Botan::BER_Decoder decoder(signature);
            Botan::BigInt r_param, s_param;
            decoder.start_sequence()
                .decode(r_param)
                .decode(s_param)
                .end_cons();

            // Prepare the signature blob as per SSH format
            auto r_bytes = r_param.serialize();
            auto s_bytes = s_param.serialize();

            Serializer ss;
            ss.writeMPInt(r_bytes);
            ss.writeMPInt(s_bytes);

            Serializer s;
            s.writeString(m_type_name);
            s.writeSecureBlob(ss.dataSecure());

            return s.data();
        }

        void ECDSAKey::registerKeyType()
        {
            KeyFactory::instance().registerKeyType(
                edcsa_sha2_nistp256_type_name,
                [](const secure_vector<uint8_t> &blob, const std::string &comment) -> std::shared_ptr<KeyBase>
                {
                    return std::make_shared<ECDSAKey>(blob, comment, edcsa_sha2_nistp256_type_name);
                },
                [](const secure_vector<uint8_t> &blob) -> std::vector<uint8_t>
                {
                    return ECDSAKey::extractPub(blob);
                },
                [](Deserializer &d)
                {
                    return ECDSAKey::skipBlob(d);
                });
            KeyFactory::instance().registerKeyType(
                edcsa_sha2_nistp384_type_name,
                [](const secure_vector<uint8_t> &blob, const std::string &comment) -> std::shared_ptr<KeyBase>
                {
                    return std::make_shared<ECDSAKey>(blob, comment, edcsa_sha2_nistp384_type_name);
                },
                [](const secure_vector<uint8_t> &blob) -> std::vector<uint8_t>
                {
                    return ECDSAKey::extractPub(blob);
                },
                [](Deserializer &d)
                {
                    return ECDSAKey::skipBlob(d);
                });
            KeyFactory::instance().registerKeyType(
                edcsa_sha2_nistp521_type_name,
                [](const secure_vector<uint8_t> &blob, const std::string &comment) -> std::shared_ptr<KeyBase>
                {
                    return std::make_shared<ECDSAKey>(blob, comment, edcsa_sha2_nistp521_type_name);
                },
                [](const secure_vector<uint8_t> &blob) -> std::vector<uint8_t>
                {
                    return ECDSAKey::extractPub(blob);
                },
                [](Deserializer &d)
                {
                    return ECDSAKey::skipBlob(d);
                });
        };

        void ECDSAKey::lock(secure_vector<uint8_t> &password)
        {
            protectData(*m_priv_key, password);
            m_priv_key.reset();
        }

        bool ECDSAKey::unlock(secure_vector<uint8_t> &password)
        {
            auto unprotected = unprotectData(password);
            if (!unprotected)
                return false;

            auto rsa_key = dynamic_cast<Botan::ECDSA_PrivateKey *>(unprotected.release());
            if (!rsa_key)
            {
                // Should not happen, but if this occurs, we have a serious problem
                throw std::runtime_error("Unlocked key is not ECDSA_PrivateKey");
            }

            m_priv_key = std::unique_ptr<Botan::ECDSA_PrivateKey>(rsa_key);
            return m_priv_key != nullptr;
        }
    }
}