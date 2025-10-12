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
#include <libssha/key/key-manager.h>
namespace nglab
{
    namespace libssha
    {
        class KeyManager;
        class KeyBase;
        class Session;
        /**
         * @brief Observer interface for key manager events.
         *
         * This interface allows implementing classes to receive notifications
         * about key addition and removal events from the KeyManager.
         */
        class KeyManagerObserver
        {
        public:
            KeyManagerObserver()
            {
                KeyManager::registerObserver(this);
            }
            /**
             * @brief Virtual destructor for KeyManagerObserver.
             */
            virtual ~KeyManagerObserver()
            {
                KeyManager::unregisterObserver(this);
            }

            /**
             * @brief Called when a key was added to the KeyManager.
             * @param key The key that was added.
             */
            virtual void onKeyAdded(KeyBasePtr key) = 0;
            /**
             * @brief Called before a key is removed from the KeyManager.
             * @param key The key that is about to be removed.
             */
            virtual void onKeyPreRemove(KeyBasePtr key) = 0;
            /**
             * @brief Called when a key was removed from the KeyManager.
             * @param fingerprint The fingerprint of the key that was removed.
             */
            virtual void onKeyRemoved(const std::string &fingerprint) = 0;
            /**
             * @brief Called when all keys are cleared from the KeyManager.
             */
            virtual void onKeysCleared() = 0;
            /**
             * @brief Called when a key is used in a session.
             * @param key The key that was used.
             * @param session The session in which the key was used.
             */
            virtual void onKeyUsed(KeyBasePtr key, const Session* session) = 0;
            /**
             * @brief Called when a key usage is declined in a session.
             * @param key The key that was declined.
             * @param session The session in which the key usage was declined.
             */
            virtual void onKeyDeclined(KeyBasePtr key, const Session* session) = 0;
            /**
             * @brief Called when the KeyManager is locked.
             */
            virtual void onLocked() = 0;
            /**
             * @brief Called when the KeyManager is unlocked.
             */
            virtual void onUnlocked() = 0;
        };
    }
}