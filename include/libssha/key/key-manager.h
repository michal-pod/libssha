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
#include <set>
#include <vector>
#include <memory>
#include <libssha/utils/secure_vector.h>
#include <libssha/messages/identities-answer.h>
#include <libssha/messages/add-identity.h>
#include <libssha/key/key.h>
#include <libssha/utils/logger.h>
#include <libssha/key/lock-provider.h>

namespace nglab
{
    namespace libssha
    {
        class Session;
        class KeyManagerObserver;
        struct PubKeyItem
        {
            std::string fingerprint;
            std::string type;
            std::string comment;
            std::vector<uint8_t> blob;
        };

        typedef std::shared_ptr<KeyBase> KeyBasePtr;
        using KeyList = std::vector<KeyBasePtr>;
        using PubKeyItemList = std::vector<PubKeyItem>;
        class KeyManager : public LogEnabler
        {
        public:
            /**
             * @brief Get the singleton instance of KeyManager
             * @return KeyManager& The singleton instance
             */
            static KeyManager &instance()
            {
                static KeyManager instance;
                return instance;
            }

            /**
             * @brief Add a key to the key manager
             * @param type The key type (e.g., "ssh-ed25519", "ssh-rsa", etc.)
             * @param blob The key blob
             * @param comment The key comment
             */
            KeyBasePtr addKey(std::string type, const secure_vector<uint8_t> &blob, const std::string &comment);

            /**
             * @brief Add a key to the key manager
             * @param msg The AddIdentityMessage containing the key information
             */
            void addKey(AddIdentityMessage &msg);

            /**
             * @brief Remove a key from the key manager
             * @param type The key type (e.g., "ssh-ed25519", "ssh-rsa", etc.)
             * @param blob The key blob
             */
            void removeKey(const std::vector<uint8_t> &blob);

            /**
             * @brief Remove all keys from the key manager
             */
            void removeAllKeys();

            /**
             * @brief List all keys in the key manager
             * @return IdentitiesAnswerMessage The message containing the list of keys
             */
            PubKeyItemList listKeys(const Session &session) const;

            /**
             * @brief Sign data with the specified key
             * @param key_blob The key blob of the key to be used for signing
             * @param data The data to be signed
             * @return std::string The signature
             * @throws std::runtime_error if the key is not found or signing fails
             */
            std::vector<uint8_t> signData(const std::vector<uint8_t> &key_blob, const std::vector<uint8_t> &data, uint32_t flags);

            /**
             * @brief Cleanup expired keys from the key manager
             *
             * This function should be called every second to remove keys that have exceeded their lifetime.
             */
            void cleanupExpiredKeys();

            /**
             * @brief Get a key by its blob
             * @param key_blob The key blob
             * @return KeyBasePtr The key object
             */
            KeyBasePtr getKey(const std::vector<uint8_t> &key_blob);

            /**
             * @brief Get a key by its fingerprint
             * @param fingerprint The key fingerprint
             */
            KeyBasePtr getKeyByFingerprint(const std::string &fingerprint);

            /**
             * @brief Lock all keys with the given passphrase
             * @param passphrase The passphrase to lock the keys
             */
            void lock(secure_vector<uint8_t> passphrase);

            /**
             * @brief Unlock all keys with the given passphrase
             * @param passphrase The passphrase to unlock the keys
             */
            void unlock(secure_vector<uint8_t> passphrase);

            /**
             * @brief Check if the key manager is locked
             * @return true if locked, false otherwise
             */
            bool isLocked() const { return m_locked; }

            /**
             * @brief Register an observer to receive key manager events
             * @param observer The observer to register
             */
            static void registerObserver(KeyManagerObserver *observer);

            /**
             * @brief Unregister an observer from receiving key manager events
             * @param observer The observer to unregister
             */
            static void unregisterObserver(KeyManagerObserver *observer);

            /**
             * @brief Set the lock provider for the key manager
             * @param provider The lock provider to set
             */
            static void setLockProvider(LockProvider* provider);

            /**
             * @brief Emit a key used event to all registered observers
             * This is only public method because it needs to be called from Session.
             * @param key The key that was used
             * @param session The session in which the key was used
             */
            void emitKeyUsed(KeyBasePtr key, const Session *session) const;

            /**
             * @brief Emit a key declined event to all registered observers
             * This is only public method because it needs to be called from Session.
             * @param key The key that was declined
             * @param session The session in which the key usage was declined
             */
            void emitKeyDeclined(KeyBasePtr key, const Session *session) const;

            /**
             * @brief Get the list of all keys
             * @return const KeyList& The list of keys
             */
            const KeyList &keys() const { return m_keys; }

        private:
            KeyManager();
            KeyList::iterator findKey(const std::vector<uint8_t> &key_blob);
            KeyList m_keys;
            bool m_locked{false};
            std::set<KeyManagerObserver *> m_observers;
            size_t m_failed_attempts{0};
            std::chrono::steady_clock::time_point m_locked_until;
            std::unique_ptr<LockProvider> m_lock_provider;

            // Event emiters
            void emitKeyAdded(KeyBasePtr key) const;
            void emitKeyPreRemove(KeyBasePtr key) const;
            void emitKeyRemoved(const std::string &fingerprint) const;
            void emitKeysCleared() const;
            void emitLocked() const;
            void emitUnlocked() const;
        };
    } // namespace libssha
} // namespace nglab