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
#include <libssha/agent/session.h>
#include <libssha/messages/message.h>
#include <libssha/messages/add-identity.h>
#include <libssha/messages/sign-request.h>
#include <libssha/messages/sign-response.h>
#include <libssha/messages/extension.h>
#include <libssha/messages/lock-message.h>
#include <libssha/messages/remove-identity.h>
#include <libssha/utils/logger.h>
#include <libssha/key/key-manager.h>
#include <libssha/extensions/openssh-session-bind.h>
#include <libssha/messages/userauth-request.h>

#include <string>
namespace nglab
{
    namespace libssha
    {
        Session::Session() : LogEnabler("Session")
        {
        }

        Session::~Session()
        {
            if (m_confirmation_thread.joinable())
            {
                m_confirmation_thread.join();
            }

            if (m_key_selection_thread.joinable())
            {
                m_key_selection_thread.join();
            }
        }

        bool Session::process(const uint8_t *data, size_t length)
        {
            if (m_temp_buffer.size() > 0)
            {
                m_temp_buffer.insert(m_temp_buffer.end(), data, data + length);
                bool result = processReal(m_temp_buffer.data(), m_temp_buffer.size());
                m_temp_buffer.clear();
                return result;
            }

            if (length < 5)
            {
                m_temp_buffer.insert(m_temp_buffer.end(), data, data + length);
                return true;
            }

            return processReal(data, length);
        }

        bool Session::processReal(const uint8_t *data, size_t length)
        {
            Message msg(data, length);
            auto &km = KeyManager::instance();

            if (km.isLocked() && msg.type() != SSH_AGENTC_UNLOCK)
            {
                log.warning("KeyManager is locked; rejecting message of type {}", msg.typeName());
                failureResponse();
                return false;
            }

            log.debug("Processing message of type {} ({})", msg.typeName(), msg.type());
            if (msg.type() == SSH_AGENTC_ADD_IDENTITY || msg.type() == SSH_AGENTC_ADD_IDENTITY_CONSTRAINED)
            {
                return processAddIdentity(msg);
            }
            else if (msg.type() == SSH_AGENTC_REMOVE_IDENTITY)
            {
                return processRemoveIdentity(msg);
            }
            else if (msg.type() == SSH_AGENTC_REMOVE_ALL_IDENTITIES)
            {
                processRemoveAllIdentity();
                return true;
            }
            else if (msg.type() == SSH_AGENTC_SIGN_REQUEST)
            {
                if (m_waiting_for_confirmation)
                {
                    throw std::logic_error("Multiple connections using single Session instance");
                }

                // Copy data to avoid dangling pointer in another thread
                std::vector<uint8_t> msg_data(data, data + length);

                m_confirmation_thread = std::thread([this, msg_data]()
                                                    {
                    // Message data should not get out of scope until processing is done
                    // because socket should be blocked
                    m_waiting_for_confirmation = true;
                    Message msg(msg_data.data(), msg_data.size());
                    processSignRequest(msg);
                    m_waiting_for_confirmation = false; });

                if (!m_async_operation)
                {
                    m_confirmation_thread.join();
                }

                return true;
            }
            else if (msg.type() == SSH_AGENTC_REQUEST_IDENTITIES)
            {
                if (m_waiting_for_key_selection)
                {
                    throw std::logic_error("Multiple connections using single Session instance");
                }

                // Copy data to avoid dangling pointer in another thread
                std::vector<uint8_t> msg_data(data, data + length);

                m_key_selection_thread = std::thread([this, msg_data]()
                                                     {
                    m_waiting_for_key_selection = true;
                    Message msg(msg_data.data(), msg_data.size());
                    processRequestIdentities(msg);
                    m_waiting_for_key_selection = false;
                    });

                if (!m_async_operation)
                {
                    m_key_selection_thread.join();
                }

                return true;
            }
            else if (msg.type() == SSH_AGENTC_EXTENSION)
            {
                return processExtension(msg);
            }
            else if (msg.type() == SSH_AGENTC_LOCK)
            {
                return processLock(msg);
            }
            else if (msg.type() == SSH_AGENTC_UNLOCK)
            {
                return processUnlock(msg);
            }
            else if (msg.type() == SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES)
            {
                // Deprecated message type, treat as REMOVE_ALL_IDENTITIES
                processRemoveAllIdentity();
                return true;
            }
            else
            {
                log.error("Unsupported message type: {} ({})", msg.typeName(), msg.type());
                failureResponse();
            }

            return false;
        }

        bool Session::processAddIdentity(const Message &msg)
        {
            auto &km = KeyManager::instance();

            try
            {
                AddIdentityMessage add_msg(msg);
                log.debug("Adding identity: type={}, comment={}",
                          add_msg.keyType(),
                          add_msg.keyComment());
                km.addKey(add_msg);
                successResponse();
            }
            catch (const std::exception &e)
            {
                log.error("Failed to parse AddIdentityMessage: {}", e.what());
                failureResponse();
                return false;
            }
            return true;
        }

        void Session::processRemoveAllIdentity()
        {
            auto &km = KeyManager::instance();
            log.info("Removing all identities");
            km.removeAllKeys();
            successResponse();
        }

        bool Session::processRemoveIdentity(const Message &msg)
        {
            try
            {
                RemoveIdentityMessage remove_msg(msg);

                auto &km = KeyManager::instance();
                km.removeKey(remove_msg.keyBlob());
                successResponse();
            }
            catch (const std::exception &e)
            {
                log.error("Failed to parse RemoveIdentityMessage: {}", e.what());
                failureResponse();
                return false;
            }
            return true;
        }

        bool Session::processSignRequest(const Message &msg)
        {
            auto &km = KeyManager::instance();

            try
            {
                SignRequestMessage sign_msg(msg);
                log.debug("Signing request with key blob size: {}, data size: {}, flags: {}",
                          sign_msg.keyBlob().size(),
                          sign_msg.data().size(),
                          sign_msg.flags());
                log.debug("Current session bindings count: {}", m_session_bindings.size());

                auto key = km.getKey(sign_msg.keyBlob());
                if (!key)
                {
                    log.error("Key not found for signing");
                    throw std::runtime_error("Key not found for signing");
                }

                if (key->destConstraints().size() > 0)
                {
                    log.debug("Key has destination constraints, checking against session bindings");
                    if (m_session_bindings.size() == 0)
                    {
                        log.warning("refusing sign request: no session bindings available");
                        throw std::runtime_error("Session has no bindings");
                    }

                    UserAuthRequestMessage userauth_msg(sign_msg.data());

                    if (!key->permitted(*this, userauth_msg.username(), m_match_info))
                    {
                        log.warning("Key not permitted by destination constraints");
                        throw std::runtime_error("Key not permitted by destination constraints");
                    }

                    if (userauth_msg.sessionId() != m_session_bindings.back().session_id)
                    {
                        log.warning("Session ID is not last bound session ID");
                        throw std::runtime_error("Session ID does not match any session bindings");
                    }
                    else
                    {
                        log.debug("Session ID matches a session binding");
                    }
                }
                else
                {
                    log.debug("Key has no destination constraints");
                }

                if ((key->confirmRequired() || requiresConfirmation(key)))
                {
                    if (!confirmRequest(*key))
                    {
                        log.warning("Sign request not confirmed by user");
                        km.emitKeyDeclined(key, this);
                        failureResponse();
                        m_match_info.clear();
                        return false;
                    }
                }

                auto signature = key->sign(sign_msg.data(), sign_msg.flags());

                km.emitKeyUsed(key, this);

                m_match_info.clear();

                SignResponseMessage response_msg;
                response_msg.setSignature(signature);
                auto response = response_msg.serialize();
                send(response);
            }
            catch (const std::exception &e)
            {
                log.error("Failed to process SignRequestMessage: {}", e.what());
                failureResponse();
                return false;
            }
            return true;
        }

        void Session::processRequestIdentities(const Message &msg)
        {
            auto &km = KeyManager::instance();
            log.debug("Processing request for identities");
            auto items = km.listKeys(*this);
            IdentitiesAnswerMessage response_msg;
            for (const auto &item : items)
            {
                response_msg.addIdentity(item.blob, item.comment);
            }
            auto response = response_msg.serialize();
            send(response);
        }

        bool Session::processExtension(const Message &msg)
        {
            try
            {
                ExtensionMessage ext_msg(msg);
                log.debug("Processing extension: {}", ext_msg.extensionName());

                if (processExtensionMessage(ext_msg))
                {
                    successResponse();
                    return true;
                }

                if (ext_msg.extensionName() != "session-bind@openssh.com")
                {
                    log.error("Unsupported extension: {}", ext_msg.extensionName());
                    failureResponse();
                    return false;
                }

                OpenSSHSessionBind *ext = dynamic_cast<OpenSSHSessionBind *>(ext_msg.extension().get());
                if (!ext)
                {
                    log.error("Failed to cast extension to OpenSSHSessionBind");
                    throw std::runtime_error("Invalid extension type");
                }
                m_is_forwarded |= ext->forwarded();
                m_session_bindings.emplace_back(ext->hostKey(), ext->sessionID(), ext->forwarded());
                successResponse();
            }
            catch (const std::exception &e)
            {
                log.error("Failed to process extension message: {}", e.what());
                m_binding_failed = true;
                m_session_bindings.clear();
                failureResponse();
                return false;
            }
            return true;
        }

        bool Session::processLock(const Message &msg)
        {
            try
            {
                LockMessage lock_msg(msg);
                log.debug("Processing lock request");
                auto &km = KeyManager::instance();
                km.lock(lock_msg.password());
                successResponse();
            }
            catch (const std::exception &e)
            {
                log.error("Failed to process lock message: {}", e.what());
                failureResponse();
                return false;
            }
            return true;
        }

        bool Session::processUnlock(const Message &msg)
        {
            try
            {
                UnlockMessage unlock_msg(msg);
                log.debug("Processing unlock request");
                auto &km = KeyManager::instance();
                km.unlock(unlock_msg.password());
                successResponse();
            }
            catch (const std::exception &e)
            {
                log.error("Failed to process unlock message: {}", e.what());
                failureResponse();
                return false;
            }
            return true;
        }

        void Session::successResponse()
        {
            SuccessMessage success_msg;
            auto response = success_msg.serialize();
            send(response);
        }

        void Session::failureResponse()
        {
            FailureMessage fail_msg;
            auto response = fail_msg.serialize();
            send(response);
        }
    }
}
