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
#include <libssha/key/key.h>
#include <libssha/agent/session.h>
#include <libssha/utils/logger.h>
namespace nglab
{
    namespace libssha
    {
        bool KeyBase::permittedByConstraints(const std::vector<uint8_t> &from_key,
                                             const std::vector<uint8_t> &to_key,
                                             const std::string &user,
                                             MatchInfoOpt mi) const
        {
            Logger log(Logger::instance(), "KeyBase::permittedByConstraints");
            for (const auto &constraint : m_dest_constraints)
            {
                if (constraint.matches(from_key, to_key, user, mi))
                {
                    log.vdebug("Key {} permitted by destination constraint", comment());
                    return true;
                }
            }
            log.info("Key {} not permitted by any destination constraint", comment());
            return false;
        }

        // identity_permitted
        bool KeyBase::permitted(const Session &session, std::string user, MatchInfoOpt mi) const
        {
            Logger log(Logger::instance(), "KeyBase::permitted");
            if (m_dest_constraints.size() == 0)
            {
                log.vdebug("key {} has no destination constraints, permitting by default", comment());
                return true;
            }

            if (session.bindingFailed())
            {
                log.warning("previous binding failed, refusing key {}", comment());
                return false;
            }

            if (session.sessionBindings().size() == 0)
            {
                return true;
            }

            std::vector<uint8_t> from_key;

            for (size_t i = 0; i < session.sessionBindings().size(); i++)
            {
                const auto &s = session.sessionBindings()[i];
                if (s.host_key.size() == 0)
                {
                    log.error("session binding has empty host key, refusing key {}", comment());
                    return false;
                }

                std::string user_to_check;
                if (i == session.sessionBindings().size() - 1)
                {
                    user_to_check = user;
                    if (s.forwarded && user_to_check.size())
                    {
                        log.error("tried to sign on forwarding hop, refusing key {}", comment());
                        return false;
                    }
                }
                else if (!s.forwarded)
                {
                    log.error("tried to forward though signing bind, refusing key {}", comment());
                    return false;
                }

                if (!permittedByConstraints(from_key, s.host_key, user_to_check, mi))
                {
                    log.info("key {} not permitted by constraints for session binding {}", comment(), i);
                    return false;
                }

                from_key = s.host_key;
            }

            auto &last_binding = session.sessionBindings().back();
            if (last_binding.forwarded && user.empty() && !permittedByConstraints(last_binding.host_key, {}, ""))
            {
                log.debug("key {} permitted at host but not after, refusing", comment());
                return false;
            }

            return true;
        }
    }
}