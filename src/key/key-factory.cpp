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
#include <libssha/key/key-factory.h>
#include <stdexcept>
#include "config.h"

#ifdef USE_BOTAN
#include <libssha/providers/botan/eddsa-key.h>
#include <libssha/providers/botan/rsa-key.h>
#include <libssha/providers/botan/edcsa-key.h>
#include <libssha/providers/botan/eddsa-pub.h>
#include <libssha/providers/botan/rsa-pub.h>
#include <libssha/providers/botan/edcsa-pub.h>
#endif

namespace nglab
{
    namespace libssha
    {

        KeyFactory &KeyFactory::instance()
        {
            static KeyFactory instance;
            return instance;
        }

        std::shared_ptr<KeyBase> KeyFactory::createKey(const string &type, const secure_vector<uint8_t> &blob, const string &comment)
        {
            auto it = instance().m_creators.find(type);
            if (it != instance().m_creators.end())
            {
                return it->second(blob, comment);
            }
            else
            {
                throw std::runtime_error("KeyFactory: unknown key type: " + type);
            }
        }

        std::shared_ptr<PubKeyBase> KeyFactory::createPubKey(const string &type, const vector<uint8_t> &blob)
        {
            auto it = instance().m_pubkey_creators.find(type);
            if (it != instance().m_pubkey_creators.end())
            {
                return it->second(blob);
            }
            else
            {
                throw std::runtime_error("KeyFactory: unknown public key type: " + type);
            }
        }

        void KeyFactory::skipKeyBlob(const string &type, Deserializer &d)
        {
            auto it = instance().m_skippers.find(type);
            if (it != instance().m_skippers.end())
            {
                it->second(d);
            }
            else
            {
                throw std::runtime_error("KeyFactory: unknown key type for skipping blob: " + type);
            }
        }

        std::vector<uint8_t> KeyFactory::extractPubKey(const string &type, const secure_vector<uint8_t> &blob)
        {
            auto it = instance().m_extractors.find(type);
            if (it != instance().m_extractors.end())
            {
                return it->second(blob);
            }
            else
            {
                throw std::runtime_error("KeyFactory: unknown key type for extracting pubkey: " + type);
            }
        }

        void KeyFactory::registerKeyType(const string &type,
                                         CreatorFunc creator, ExtractPubKeyFunc extractPubKey, SkipBlobFunc skipBlob)
        {
            KeyFactory &kf = instance();
            if (kf.m_creators.find(type) != kf.m_creators.end() ||
                kf.m_extractors.find(type) != kf.m_extractors.end() ||
                kf.m_skippers.find(type) != kf.m_skippers.end())
            {
                throw std::runtime_error("KeyFactory: key type already registered: " + type);
            }

            kf.m_creators[type] = creator;
            kf.m_extractors[type] = extractPubKey;
            kf.m_skippers[type] = skipBlob;
        }

        void KeyFactory::registerPubKeyType(const string &type,
                                           CreatePubKeyFunc creator)
        {
            KeyFactory &kf = instance();
            if (kf.m_pubkey_creators.find(type) != kf.m_pubkey_creators.end())
            {
                throw std::runtime_error("KeyFactory: public key type already registered: " + type);
            }

            kf.m_pubkey_creators[type] = creator;
        }

        // Provide a stub for initializeKeyTypes if needed, or leave for implementation elsewhere
        void KeyFactory::initializeKeyTypes()
        {
            static bool initialized = false;
            if (!initialized)
            {
                #ifdef USE_BOTAN
                // Private key types provided here
                Ed25519Key::registerType();
                Ed448Key::registerType();
                RsaKey::registerType();
                ECDSAKey::registerKeyType();

                // Public key types provided here
                ED25519Pub::registerType();
                ED448Pub::registerType();
                RSAPub::registerType();
                ECDSAPub::registerKeyType();
                #endif
                initialized = true;
            }
        }

        KeyFactory::KeyFactory() = default;

    } // namespace libssha
} // namespace nglab
