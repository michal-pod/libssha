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
            auto pubKey = KeyFactory::extractPubKey(type, blob); // just to check if type is supported
            auto it = findKey(pubKey);
            if (it != m_keys.end())
            {
                log.info("Key already exists, removing old instance before adding new one");
                m_keys.erase(it);
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
            auto it = findKey(blob);
            if (it != m_keys.end())
            {
                emitKeyPreRemove(*it);
                string fingerprint = (*it)->fingerprint();
                m_keys.erase(it);
                emitKeyRemoved(fingerprint);
            }
            // else: key not found, do nothing
        }

        void KeyManager::removeAllKeys()
        {
            std::list<std::string> fingerprints;
            for (const auto &key : m_keys)
            {
                emitKeyPreRemove(key);
                fingerprints.push_back(key->fingerprint());
            }

            m_keys.clear();

            for (const auto &fp : fingerprints)
            {
                emitKeyRemoved(fp);
            }

            emitKeysCleared();
        }

        PubKeyItemList KeyManager::listKeys(const Session &session) const
        {
            PubKeyItemList items;

            IdentitiesAnswerMessage msg;
            for (const auto &key : m_keys)
            {
                if (key->permitted(session, ""))
                {
                    items.push_back({key->fingerprint(), key->type(), key->comment(), key->pubBlob()});
                }
            }
            log.debug("Listing {} from {} identities", items.size(), m_keys.size());

            return items;
        }

        std::vector<uint8_t> KeyManager::signData(const std::vector<uint8_t> &key_blob, const std::vector<uint8_t> &data, uint32_t flags)
        {
            auto it = findKey(key_blob);
            if (it != m_keys.end())
            {
                return (*it)->sign(data, flags);
            }
            throw std::runtime_error("Key not found");
        }

        std::vector<std::shared_ptr<KeyBase>>::iterator KeyManager::findKey(const std::vector<uint8_t> &key_blob)
        {
            return std::find_if(m_keys.begin(), m_keys.end(),
                                [&key_blob](const std::shared_ptr<KeyBase> &key)
                                {
                                    return key->pubBlob() == key_blob;
                                });
        }

        void KeyManager::cleanupExpiredKeys()
        {
            for (auto it = m_keys.begin(); it != m_keys.end();)
            {
                if ((*it)->expired())
                {
                    log.debug("Removing expired key: {}", (*it)->fingerprint());
                    emitKeyPreRemove(*it);
                    std::string fingerprint = (*it)->fingerprint();
                    it = m_keys.erase(it);
                    emitKeyRemoved(fingerprint);
                }
                else
                {
                    ++it;
                }
            }
        }

        std::shared_ptr<KeyBase> KeyManager::getKey(const std::vector<uint8_t> &key_blob)
        {
            auto it = findKey(key_blob);
            if (it != m_keys.end())
            {
                return *it;
            }
            return nullptr;
        }

        std::shared_ptr<KeyBase> KeyManager::getKeyByFingerprint(const std::string &fingerprint)
        {
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
            if(!m_lock_provider)
            {
                // Only throwing exception here could be ignored as normal error
                // so we abort to make sure developer notices the misconfiguration.
                log.error("No lock provider set, cannot lock");
                abort();
            }

            if (m_locked)
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

            emitLocked();
            m_locked = true;
        }

        void KeyManager::unlock(secure_vector<uint8_t> passphrase)
        {
            if (!m_locked)
            {
                throw std::runtime_error("Agent is not locked");
            }

            if(!m_lock_provider)
            {
                log.error("No lock provider set, cannot unlock");
                abort();
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
                if(!m_lock_provider->verify(passphrase))
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
            emitUnlocked();
            m_locked = false;
            m_failed_attempts = 0;            
        }

        void KeyManager::registerObserver(KeyManagerObserver *observer)
        {
            auto &instance = KeyManager::instance();
            auto &log = instance.log;
            log.vdebug("Registering observer with type {}", typeid(*observer).name());
            instance.m_observers.insert(observer);
        }

        void KeyManager::unregisterObserver(KeyManagerObserver *observer)
        {
            auto &instance = KeyManager::instance();
            instance.m_observers.erase(observer);
        }

        void KeyManager::setLockProvider(LockProvider* provider)
        {
            auto &instance = KeyManager::instance();
            instance.m_lock_provider.reset(provider);
        }

        void KeyManager::emitKeyAdded(KeyBasePtr key) const
        {
            for (auto observer : m_observers)
            {
                observer->onKeyAdded(key);
            }
        }

        void KeyManager::emitKeyPreRemove(KeyBasePtr key) const
        {
            for (auto observer : m_observers)
            {
                observer->onKeyPreRemove(key);
            }
        }

        void KeyManager::emitKeyRemoved(const std::string &fingerprint) const
        {
            for (auto observer : m_observers)
            {
                observer->onKeyRemoved(fingerprint);
            }
        }

        void KeyManager::emitKeysCleared() const
        {
            for (auto observer : m_observers)
            {
                observer->onKeysCleared();
            }
        }

        void KeyManager::emitKeyUsed(KeyBasePtr key, const Session *session) const
        {
            for (auto observer : m_observers)
            {
                observer->onKeyUsed(key, session);
            }
        }

        void KeyManager::emitKeyDeclined(KeyBasePtr key, const Session *session) const
        {
            for (auto observer : m_observers)
            {
                observer->onKeyDeclined(key, session);
            }
        }

        void KeyManager::emitLocked() const
        {
            for (auto observer : m_observers)
            {
                observer->onLocked();
            }
        }

        void KeyManager::emitUnlocked() const
        {
            for (auto observer : m_observers)
            {
                observer->onUnlocked();
            }
        }
    } // namespace libssha
} // namespace nglab
