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
        Session::Session()
        {
        }

        Session::~Session()
        {
            // Safety net only, derived classes should have joined already
            joinWorkers();
        }

        void Session::joinWorkers()
        {
            stopProcessing();

            if (m_worker.joinable())
            {
                m_worker.join();
            }
        }

        void Session::stopProcessing()
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_stopping = true;
            m_requests.clear();
            m_queue_cv.notify_all();
        }

        bool Session::hasPendingOperations() const
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            return m_processing || !m_requests.empty();
        }

        bool Session::process(const uint8_t *data, size_t length)
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            if (m_stopping)
            {
                return false;
            }

            m_input_buffer.insert(m_input_buffer.end(), data, data + length);

            while (m_input_buffer.size() >= 4)
            {
                const uint32_t message_length = (static_cast<uint32_t>(m_input_buffer[0]) << 24) |
                                                (static_cast<uint32_t>(m_input_buffer[1]) << 16) |
                                                (static_cast<uint32_t>(m_input_buffer[2]) << 8) |
                                                static_cast<uint32_t>(m_input_buffer[3]);

                // Like OpenSSH, a message that cannot be framed closes the connection
                if (message_length == 0 || message_length > MaxMessageLength)
                {
                    log.error("Invalid message length {}, closing connection", message_length);
                    m_input_buffer.clear();
                    return false;
                }

                const size_t frame_length = 4 + static_cast<size_t>(message_length);
                if (m_input_buffer.size() < frame_length)
                {
                    break;
                }

                if (m_requests.size() >= MaxQueuedRequests)
                {
                    log.error("Too many queued requests, closing connection");
                    m_input_buffer.clear();
                    return false;
                }

                m_requests.emplace_back(m_input_buffer.begin(), m_input_buffer.begin() + frame_length);
                m_input_buffer.erase(m_input_buffer.begin(), m_input_buffer.begin() + frame_length);
            }

            if (m_requests.empty())
            {
                return true;
            }

            if (!m_worker.joinable())
            {
                m_worker = std::thread(&Session::processQueue, this);
            }
            m_queue_cv.notify_all();

            if (!m_async_operation)
            {
                m_queue_cv.wait(lock, [this]()
                                { return m_stopping || (m_requests.empty() && !m_processing); });
            }

            return true;
        }

        void Session::processQueue()
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            while (true)
            {
                m_queue_cv.wait(lock, [this]()
                                { return m_stopping || !m_requests.empty(); });
                if (m_stopping)
                {
                    return;
                }

                auto request = std::move(m_requests.front());
                m_requests.pop_front();
                m_processing = true;

                lock.unlock();
                processRequest(request);
                lock.lock();

                m_processing = false;
                m_queue_cv.notify_all();
            }
        }

        void Session::processRequest(const secure_vector<uint8_t> &request)
        {
            m_responded = false;

            // An exception must not leave the worker thread, it would terminate the process
            try
            {
                dispatchRequest(Message(request.data(), request.size()));
            }
            catch (const std::exception &e)
            {
                log.error("Failed to process request: {}", e.what());
            }
            catch (...)
            {
                log.error("Failed to process request: unknown exception");
            }

            if (!m_responded)
            {
                try
                {
                    log.warning("Request was not answered, sending failure");
                    failureResponse();
                }
                catch (...)
                {
                    log.error("Failed to send failure response");
                }
            }
        }

        void Session::dispatchRequest(const Message &msg)
        {
            auto &km = KeyManager::instance();

            // Same as OpenSSH: a locked agent lists no keys, still accepts extensions
            // (session-bind) and refuses everything else except unlock
            if (km.isLocked() && msg.type() != SSH_AGENTC_UNLOCK && msg.type() != SSH_AGENTC_EXTENSION)
            {
                if (msg.type() == SSH_AGENTC_REQUEST_IDENTITIES)
                {
                    log.info("KeyManager is locked; sending empty identities list");
                    IdentitiesAnswerMessage response_msg;
                    auto response = response_msg.serialize();
                    respond(response);
                    return;
                }

                log.warning("KeyManager is locked; rejecting message of type {}", msg.typeName());
                failureResponse();
                return;
            }

            log.debug("Processing message of type {} ({})", msg.typeName(), msg.type());
            if (msg.type() == SSH_AGENTC_ADD_IDENTITY || msg.type() == SSH_AGENTC_ADD_IDENTITY_CONSTRAINED)
            {
                processAddIdentity(msg);
            }
            else if (msg.type() == SSH_AGENTC_REMOVE_IDENTITY)
            {
                processRemoveIdentity(msg);
            }
            else if (msg.type() == SSH_AGENTC_REMOVE_ALL_IDENTITIES)
            {
                processRemoveAllIdentity();
            }
            else if (msg.type() == SSH_AGENTC_SIGN_REQUEST)
            {
                processSignRequest(msg);
            }
            else if (msg.type() == SSH_AGENTC_REQUEST_IDENTITIES)
            {
                processRequestIdentities(msg);
            }
            else if (msg.type() == SSH_AGENTC_EXTENSION)
            {
                processExtension(msg);
            }
            else if (msg.type() == SSH_AGENTC_LOCK)
            {
                processLock(msg);
            }
            else if (msg.type() == SSH_AGENTC_UNLOCK)
            {
                processUnlock(msg);
            }
            else if (msg.type() == SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES)
            {
                // Deprecated message type, treat as REMOVE_ALL_IDENTITIES
                processRemoveAllIdentity();
            }
            else
            {
                log.error("Unsupported message type: {} ({})", msg.typeName(), msg.type());
                failureResponse();
            }
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

                auto signature = km.signData(sign_msg.keyBlob(), sign_msg.data(), sign_msg.flags());

                km.emitKeyUsed(key, this);

                m_match_info.clear();

                SignResponseMessage response_msg;
                response_msg.setSignature(signature);
                auto response = response_msg.serialize();
                respond(response);
            }
            catch (const std::exception &e)
            {
                log.error("Failed to process SignRequestMessage: {}", e.what());
                failureResponse();
                return false;
            }
            return true;
        }

        void Session::processRequestIdentities([[maybe_unused]] const Message &msg)
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
            respond(response);
        }

        bool Session::processExtension(const Message &msg)
        {
            bool session_bind = false;
            try
            {
                // Read the name first, ExtensionMessage parses (and verifies) the extension
                // in its constructor and a failed session-bind must be told apart from others
                Deserializer name_reader(msg.data(), msg.length());
                name_reader.readBE32();
                name_reader.readByte();
                session_bind = name_reader.readString() == "session-bind@openssh.com";

                ExtensionMessage ext_msg(msg);
                log.debug("Processing extension: {}", ext_msg.extensionName());

                if (processExtensionMessage(ext_msg))
                {
                    successResponse();
                    return true;
                }

                if (!session_bind)
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
                // Only a failed session-bind makes destination constrained keys unusable,
                // as in OpenSSH. Other extensions get just a failure (RFC 9987, section 5.8).
                if (session_bind)
                {
                    m_binding_failed = true;
                    m_session_bindings.clear();
                }
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
            respond(response);
        }

        void Session::failureResponse()
        {
            FailureMessage fail_msg;
            auto response = fail_msg.serialize();
            respond(response);
        }

        bool Session::respond(secure_vector<uint8_t> &data)
        {
            if (m_responded)
            {
                log.error("Request was already answered, dropping another reply");
                return false;
            }

            m_responded = true;
            return send(data);
        }
    }
}
