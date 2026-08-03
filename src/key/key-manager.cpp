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
#include <libssha/key/key-manager.h>
#include <libssha/key/key.h>
#include <libssha/messages/identities-answer.h>
#include <libssha/key/key-factory.h>
#include <libssha/extensions/openssh-restrict-destination.h>
#include <libssha/key/key-manager-observer.h>
#include <mutex>
#include <list>
#include <cmath>
namespace nglab
{
    namespace libssha
    {
        KeyManager::KeyManager() : LogEnabler("KeyManager")
        {
            m_locked_until = std::chrono::steady_clock::now() - std::chrono::seconds(10);
        }

        std::shared_ptr<KeyBase> KeyManager::addKey(std::string type, const secure_vector<uint8_t> &blob, const std::string &comment)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            auto pubKey = KeyFactory::extractPubKey(type, blob); // just to check if type is supported
            auto key = findKeyNoLock(pubKey);
            if (key)
            {
                log.info("Key already exists, removing old instance before adding new one");
                m_keys.erase(std::find(m_keys.begin(), m_keys.end(), key));
            }

            auto k = KeyFactory::createKey(type, blob, comment);
            if (!k)
            {
                throw std::runtime_error("Failed to create key of type: " + type);
            }

            m_keys.push_back(k);
            return k;
        }

        void KeyManager::addKey(AddIdentityMessage &msg)
        {
            auto key = addKey(msg.keyType(), msg.keyBlob(), msg.keyComment());
            if (msg.lifetime() > 0)
            {
                key->setLifetime(msg.lifetime());
            }
            key->setConfirmRequired(msg.confirmRequired());

            auto ext = msg.extension();
            if (ext)
            {
                // attach extension to the key if needed
                OpenSSHSRestrictDestination *dest_constraint = dynamic_cast<OpenSSHSRestrictDestination *>(ext.get());
                if (dest_constraint)
                {
                    key->setDestConstraints(dest_constraint->constraints());
                }
            }

            emitKeyAdded(key);
        }

        void KeyManager::removeKey(const std::vector<uint8_t> &blob)
        {
            KeyBasePtr key;

            {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                key = findKeyNoLock(blob);
                if (key)
                {
                    m_keys.erase(std::find(m_keys.begin(), m_keys.end(), key));
                }
            }
            if (key)
            {
                emitKeyRemoved(key);
            }
            // else: key not found, do nothing
        }

        void KeyManager::removeAllKeys()
        {
            KeyList keys;
            {
                std::lock_guard<std::mutex> lock(m_state_mutex);

                keys = m_keys;

                m_keys.clear();
            }

            for (const auto &key : keys)
            {
                emitKeyRemoved(key);
            }

            emitKeysCleared();
        }

        PubKeyItemList KeyManager::listKeys(const Session &session) const
        {
            PubKeyItemList items;

            KeyList keys_copy;
            {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                keys_copy = m_keys; // make a copy to avoid holding the lock while checking permissions
            }

            IdentitiesAnswerMessage msg;
            for (const auto &key : keys_copy)
            {
                if (key->permitted(session, ""))
                {
                    items.push_back({key->fingerprint(), key->type(), key->comment(), key->pubBlob()});
                }
            }
            log.debug("Listing {} from {} identities", items.size(), keys_copy.size());

            return items;
        }

        std::vector<uint8_t> KeyManager::signData(const std::vector<uint8_t> &key_blob, const std::vector<uint8_t> &data, uint32_t flags)
        {
            auto key = findKey(key_blob);
            if (key)
            {
                return key->sign(data, flags);
            }
            throw std::runtime_error("Key not found");
        }

        KeyBasePtr KeyManager::findKey(const std::vector<uint8_t> &key_blob)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            return findKeyNoLock(key_blob);
        }

        KeyBasePtr KeyManager::findKeyNoLock(const std::vector<uint8_t> &key_blob)
        {
            auto it = std::find_if(m_keys.begin(), m_keys.end(),
                                   [&key_blob](const std::shared_ptr<KeyBase> &key)
                                   {
                                       return key->pubBlob() == key_blob;
                                   });
            if (it != m_keys.end())
            {
                return *it;
            }
            return nullptr;
        }

        void KeyManager::cleanupExpiredKeys()
        {
            KeyList expired_keys;

            {
                std::lock_guard<std::mutex> lock(m_state_mutex);
                for (auto it = m_keys.begin(); it != m_keys.end();)
                {
                    if ((*it)->expired())
                    {
                        log.debug("Removing expired key: {}", (*it)->fingerprint());
                        auto key = *it;
                        std::string fingerprint = (*it)->fingerprint();
                        expired_keys.push_back(key);
                        it = m_keys.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }
            for (const auto &key : expired_keys)
            {
                emitKeyRemoved(key);
            }
        }

        std::shared_ptr<KeyBase> KeyManager::getKey(const std::vector<uint8_t> &key_blob)
        {
            auto key = findKey(key_blob);
            if (key)
            {
                return key;
            }
            return nullptr;
        }

        std::shared_ptr<KeyBase> KeyManager::getKeyByFingerprint(const std::string &fingerprint)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            auto it = std::find_if(m_keys.begin(), m_keys.end(),
                                   [&fingerprint](const std::shared_ptr<KeyBase> &key)
                                   {
                                       return key->fingerprint() == fingerprint;
                                   });
            if (it != m_keys.end())
            {
                return *it;
            }
            return nullptr;
        }

        void KeyManager::lock(secure_vector<uint8_t> passphrase)
        {
            if (!m_lock_provider)
            {
                // Only throwing exception here could be ignored as normal error
                // so we abort to make sure developer notices the misconfiguration.
                log.error("No lock provider set, cannot lock");
                abort();
            }

            {
                std::lock_guard<std::mutex> lock(m_state_mutex);

                if (m_locked.load())
                {
                    throw std::runtime_error("Agent is already locked");
                }

                // In case we don't have any keys, use the lock provider to just store the passphrase hash
                m_lock_provider->lock(passphrase);

                // Now lock, key providers should encrypt their private keys with the passphrase
                for (auto &key : m_keys)
                {
                    key->lock(passphrase);
                }
                m_locked.store(true);
            }

            emitLocked();
        }

        void KeyManager::unlock(secure_vector<uint8_t> passphrase)
        {
            if (!m_lock_provider)
            {
                log.error("No lock provider set, cannot unlock");
                abort();
            }

            {
                std::lock_guard<std::mutex> lock(m_state_mutex);

                if (!m_locked.load())
                {
                    throw std::runtime_error("Agent is not locked");
                }

                // Simple brute-force protection: exponential backoff on failed attempts
                // When locked even valid attempts are blocked until the lock period expires
                if (std::chrono::steady_clock::now() < m_locked_until)
                {
                    m_failed_attempts++;
                    throw std::runtime_error(std::format("Too many failed unlock attempts, please wait {} seconds before retrying",
                                                         std::chrono::duration_cast<std::chrono::seconds>(m_locked_until - std::chrono::steady_clock::now()).count()));
                }

                try
                {
                    if (!m_lock_provider->verify(passphrase))
                    {
                        throw std::runtime_error("Incorrect passphrase");
                    }

                    for (auto &key : m_keys)
                    {
                        key->unlock(passphrase);
                    }
                }
                catch (...)
                {
                    m_failed_attempts++;
                    if (m_failed_attempts > 2)
                    {
                        int wait_time = static_cast<int>(floor(pow(1.8, m_failed_attempts)));
                        log.warning("Too many failed unlock attempts, locking for {} seconds", wait_time);
                        m_locked_until = std::chrono::steady_clock::now() + std::chrono::seconds(wait_time);
                    }
                    throw;
                }

                m_locked.store(false);
                m_failed_attempts = 0;
            }
            emitUnlocked();
        }

        void KeyManager::registerObserver(KeyManagerObserver *observer)
        {
            auto &instance = KeyManager::instance();
            auto &log = instance.log;
            log.vdebug("Registering observer with type {}", typeid(*observer).name());
            std::lock_guard<std::mutex> lock(instance.m_observer_mutex);
            instance.m_observers.insert(observer);
        }

        void KeyManager::unregisterObserver(KeyManagerObserver *observer)
        {
            auto &instance = KeyManager::instance();
            std::lock_guard<std::mutex> lock(instance.m_observer_mutex);
            instance.m_observers.erase(observer);
        }

        void KeyManager::setLockProvider(LockProvider *provider)
        {
            auto &instance = KeyManager::instance();
            instance.m_lock_provider.reset(provider);
        }

        void KeyManager::emitKeyAdded(KeyBasePtr key) const
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex);
            for (auto observer : m_observers)
            {
                observer->onKeyAdded(key);
            }
        }

        void KeyManager::emitKeyRemoved(KeyBasePtr key) const
        {
            std::set<KeyManagerObserver *> observers_copy;
            {
                std::lock_guard<std::mutex> lock(m_observer_mutex);
                observers_copy = m_observers; // make a copy to avoid holding the lock while notifying
            }

            for (auto observer : observers_copy)
            {
                observer->onKeyRemoved(key);
            }
        }

        void KeyManager::emitKeysCleared() const
        {
            std::set<KeyManagerObserver *> observers_copy;
            {
                std::lock_guard<std::mutex> lock(m_observer_mutex);
                observers_copy = m_observers; // make a copy to avoid holding the lock while notifying
            }

            for (auto observer : observers_copy)
            {
                observer->onKeysCleared();
            }
        }

        void KeyManager::emitKeyUsed(KeyBasePtr key, const Session *session) const
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex);
            for (auto observer : m_observers)
            {
                observer->onKeyUsed(key, session);
            }
        }

        void KeyManager::emitKeyDeclined(KeyBasePtr key, const Session *session) const
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex);
            for (auto observer : m_observers)
            {
                observer->onKeyDeclined(key, session);
            }
        }

        void KeyManager::emitLocked() const
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex);
            for (auto observer : m_observers)
            {
                observer->onLocked();
            }
        }

        void KeyManager::emitUnlocked() const
        {
            std::lock_guard<std::mutex> lock(m_observer_mutex);
            for (auto observer : m_observers)
            {
                observer->onUnlocked();
            }
        }

        size_t KeyManager::keyCount() const
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            return m_keys.size();
        }
    } // namespace libssha
} // namespace nglab
