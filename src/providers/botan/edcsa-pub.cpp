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
#include <libssha/key/pub-key.h>
#include <libssha/providers/botan/edcsa-pub.h>
#include <libssha/key/key-factory.h>
#include <libssha/utils/deserializer.h>
#include <botan/der_enc.h>
#include <botan/ec_group.h>
#include <botan/ec_point.h>
#include <botan/pubkey.h>
#include <stdexcept>
namespace nglab
{
    namespace libssha
    {

        ECDSAPub::ECDSAPub(const std::vector<uint8_t> &blob)
            : PubKeyBase(blob)
        {
            Deserializer d(blob);
            m_type = d.readString();

            // string m_type_name = d.readBlob();
            m_curve_name = d.readString();
            auto pub_data = d.readMPInt();

            if (m_curve_name == "nistp256")
            {
                m_signature_algorithm = "EMSA1(SHA-256)";
                m_botan_curve_name = "secp256r1";
            }
            else if (m_curve_name == "nistp384")
            {
                m_signature_algorithm = "EMSA1(SHA-384)";
                m_botan_curve_name = "secp384r1";
            }
            else if (m_curve_name == "nistp521")
            {
                m_signature_algorithm = "EMSA1(SHA-512)";
                m_botan_curve_name = "secp521r1";
            }
            else
            {
                throw std::runtime_error("ECDSAPub: unknown curve name: " + m_curve_name);
            }

            const auto domain = Botan::EC_Group::from_name(m_botan_curve_name);
            const auto pub_point = Botan::EC_AffinePoint(domain, pub_data);

            m_pub_key = std::make_unique<Botan::ECDSA_PublicKey>(domain, pub_point);
        }

        bool ECDSAPub::verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const
        {
            Deserializer sig_deser(signature);
            auto sig_type = sig_deser.readString();
            auto sig_blob = sig_deser.readBlob();

            Deserializer sig_blob_deser(sig_blob);
            auto r_bytes = sig_blob_deser.readMPInt();
            auto s_bytes = sig_blob_deser.readMPInt();

            Botan::DER_Encoder der;
            der.start_sequence().encode(Botan::BigInt(r_bytes)).encode(Botan::BigInt(s_bytes)).end_cons();

            auto der_signature = der.get_contents();

            Botan::PK_Verifier verifier(*m_pub_key, m_signature_algorithm, Botan::Signature_Format::DerSequence);
            return verifier.verify_message(data, der_signature);
        }

        size_t ECDSAPub::bits() const
        {
            return m_pub_key->key_length();
        }

        void ECDSAPub::registerKeyType()
        {
            KeyFactory::registerPubKeyType("ecdsa-sha2-nistp256",
                                           [](const std::vector<uint8_t> &blob) -> std::unique_ptr<PubKeyBase>
                                           {
                                               return std::make_unique<ECDSAPub>(blob);
                                           });
            KeyFactory::registerPubKeyType("ecdsa-sha2-nistp384",
                                           [](const std::vector<uint8_t> &blob) -> std::unique_ptr<PubKeyBase>
                                           {
                                               return std::make_unique<ECDSAPub>(blob);
                                           });
            KeyFactory::registerPubKeyType("ecdsa-sha2-nistp521",
                                           [](const std::vector<uint8_t> &blob) -> std::unique_ptr<PubKeyBase>
                                           {
                                               return std::make_unique<ECDSAPub>(blob);
                                           });
        }

    }
}