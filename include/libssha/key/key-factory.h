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
#pragma once
#include <string>
#include <libssha/utils/deserializer.h>
#include <functional>
#include <memory>
#include <unordered_map>
#include <libssha/utils/secure_vector.h>

namespace nglab
{
    namespace libssha
    {
        using std::shared_ptr;
        using std::string;
        using std::vector;
        class KeyBase;
        class PubKeyBase;
        /**
         * @brief Factory class for creating KeyBase objects based on key type strings
         *
         * This class allows registration of different key types with their corresponding
         * creation, public key extraction, and blob skipping functions. It provides methods
         * to create keys, skip key blobs, and extract public keys based on the key type
         */
        class KeyFactory
        {
        public:
            // Type aliases for the function signatures
            using CreatorFunc = std::function<std::shared_ptr<KeyBase>(const secure_vector<uint8_t> &, const string &)>;
            using ExtractPubKeyFunc = std::function<std::vector<uint8_t>(const secure_vector<uint8_t> &)>;
            using SkipBlobFunc = std::function<void(Deserializer &)>;
            using CreatePubKeyFunc = std::function<std::shared_ptr<PubKeyBase>(const vector<uint8_t> &)>;

            /**
             * @brief Get the singleton instance of the KeyFactory
             * @return KeyFactory& The singleton instance
             */
            static KeyFactory &instance();

            /**
             * @brief Create a KeyBase object of the specified type
             * @param type The key type string
             * @param blob The key blob
             * @param comment The key comment
             * @return shared_ptr<KeyBase> The created KeyBase object
             */
            static shared_ptr<KeyBase> createKey(const string &type, const secure_vector<uint8_t> &blob, const string &comment);

            /**
             * @brief Create a PubKeyBase object of the specified type
             * @param type The public key type string
             * @param blob The public key blob
             * @return shared_ptr<PubKeyBase> The created PubKeyBase object
             */
            static shared_ptr<PubKeyBase> createPubKey(const string &type, const vector<uint8_t> &blob);

            /**
             * @brief Skip the key blob of the specified type in the deserializer
             * @param type The key type string
             * @param d The deserializer to skip the blob in
             */
            static void skipKeyBlob(const string &type, Deserializer &d);

            /**
             * @brief Extract the public key from the key blob of the specified type
             * @param type The key type string
             * @param blob The key blob
             * @return string The extracted public key
             */
            static std::vector<uint8_t> extractPubKey(const string &type, const secure_vector<uint8_t> &blob);

            /**
             * @brief Register a key type with its corresponding functions
             * @param type The key type string
             * @param creator The function to create a KeyBase object
             * @param extractPubKey The function to extract the public key from a key blob
             * @param skipBlob The function to skip the key blob in a deserializer
             */
            static void registerKeyType(const string &type,
                                        CreatorFunc creator, ExtractPubKeyFunc extractPubKey, SkipBlobFunc skipBlob);

            /**
             * @brief Register a public key type with its corresponding creation function
             * @param type The public key type string
             * @param creator The function to create a PubKeyBase object
             */
            static void registerPubKeyType(const string &type,
                                           CreatePubKeyFunc creator);

            /**
             * @brief Initialize supported key types
             */
            static void initializeKeyTypes();

        private:
            KeyFactory();
            std::unordered_map<string, CreatorFunc> m_creators;
            std::unordered_map<string, ExtractPubKeyFunc> m_extractors;
            std::unordered_map<string, SkipBlobFunc> m_skippers;
            std::unordered_map<string, CreatePubKeyFunc> m_pubkey_creators;
        };
    } // namespace libssha
} // namespace nglab