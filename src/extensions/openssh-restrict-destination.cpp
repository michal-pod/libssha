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
#include <libssha/extensions/openssh-restrict-destination.h>

namespace nglab
{
    namespace libssha
    {

        OpenSSHHopDescriptor::OpenSSHHopDescriptor(std::vector<uint8_t> &data, std::string tag) : LogEnabler("hop" + (tag.size() > 0 ? "-" + tag : ""))
        {
            Deserializer d(data);
            m_user = d.readString();
            m_hostname = d.readString();
            auto extensions = d.readBlob();
            if (extensions.size() > 0)
            {
                log.error("Extensions in hop descriptor not supported");
                throw std::runtime_error("OpenSSHHopDescriptor: extensions not supported");
            }
            while (d.remaining() > 0)
            {
                auto key = d.readBlob();
                auto key_is_ca = d.readByte() != 0;
                log.vdebug("Key size: {}, is_ca: {}", key.size(), key_is_ca);
                m_keys.emplace_back(OpenSSHHopKey{key, key_is_ca});
            }
            log.vdebug("Hop descriptor - user: {}, hostname: {}, keys: {}", m_user, m_hostname, m_keys.size());
        }

        OpenSSHHopDescriptor::OpenSSHHopDescriptor(const std::vector<OpenSSHHopKey> &keys, std::string hostname, std::string user) : LogEnabler("hop"), m_keys(keys), m_hostname(hostname), m_user(user)
        {
        }

        std::vector<uint8_t> OpenSSHHopDescriptor::serialize() const
        {
            Serializer hs;
            hs.writeString(m_user);
            hs.writeString(m_hostname);
            // no extensions
            hs.writeBlob(std::vector<uint8_t>());
            for (const auto &k : m_keys)
            {
                hs.writeBlob(k.key);
                hs.writeByte(k.key_is_ca ? 1 : 0);
            }
                return hs.data();
        }

        bool OpenSSHHopDescriptor::matchesKey(const std::vector<uint8_t> &key) const
        {
            // This is simplified logic to match key hops. Now I don't support CA keys.
            // In future, I should implement proper CA key checking. But for now, this is sufficient.
            for (const auto &k : m_keys)
            {
                if (k.key.empty())
                {
                    log.warning("Empty key in hop descriptor");
                    return false;
                }

                if (k.key_is_ca)
                {
                    log.warning("Key is CA, this is not supported yet. Skipping.");
                    continue;
                }

                if (k.key != key)
                {
                    continue;
                }

                return true;
            }
            return false;
        }

        std::string OpenSSHHopDescriptor::toString() const
        {
            if (m_hostname.empty() && m_keys.empty() && m_user.empty())
            {
                return "Any";
            }

            std::string ret = "";
            if (m_user.size())
            {
                ret += m_user + "@";
            }
            ret += m_hostname;

            if (m_keys.size())
            {
                ret += std::format(" ({} keys)", m_keys.size());
            }

            return ret;
        }

        OpenSSHSDestinationConstraint::OpenSSHSDestinationConstraint(std::vector<uint8_t> &data) : LogEnabler("OpenSSHSDestinationConstraint")
        {
            Deserializer d(data);
            auto from_hop = d.readBlob();
            auto to_hop = d.readBlob();
            auto extensions = d.readBlob();
            if (extensions.size() > 0)
            {
                log.error("Extensions in destination constraint not supported");
                throw std::runtime_error("OpenSSHSDestinationConstraint: extensions not supported");
            }
            log.vdebug("Destination constraint - from_hop size: {}, to_hop size: {}", from_hop.size(), to_hop.size());
            OpenSSHHopDescriptor from(from_hop);
            OpenSSHHopDescriptor to(to_hop);

            if (from.hostname().empty() != from.keys().empty() || !from.user().empty())
            {
                log.error("Invalid from_hop in destination constraint");
                throw std::runtime_error("OpenSSHSDestinationConstraint: invalid from_hop");
            }

            if (to.hostname().empty() || to.keys().empty())
            {
                log.error("Invalid to_hop in destination constraint");
                throw std::runtime_error("OpenSSHSDestinationConstraint: invalid to_hop");
            }

            m_from_hop = from;
            m_to_hop = to;
        }

        OpenSSHSDestinationConstraint::OpenSSHSDestinationConstraint(const OpenSSHHopDescriptor &from, const OpenSSHHopDescriptor &to) : LogEnabler("OpenSSHSDestinationConstraint"), m_from_hop(from), m_to_hop(to)
        {
        }

        std::vector<uint8_t> OpenSSHSDestinationConstraint::serialize() const
        {
            Serializer cs;
            auto fb = m_from_hop.serialize();
            auto tb = m_to_hop.serialize();
            cs.writeBlob(fb);
            cs.writeBlob(tb);
            // no extensions
            cs.writeBlob(std::vector<uint8_t>());
                return cs.data();
        }

        // loop part of permitted_by_dest_constraints
        bool OpenSSHSDestinationConstraint::matches(const std::vector<uint8_t> &from_key,
                                                    const std::vector<uint8_t> &to_key,
                                                    const std::string &user,
                                                    MatchInfoOpt mi) const
        {
            // Check from key matches
            if (from_key.empty())
            {
                if (m_from_hop.hostname().size() || m_from_hop.keys().size())
                {
                    return false;
                }
            }
            else if (!m_from_hop.matchesKey(from_key))
            {
                return false;
            }

            // Check to key matches
            if (to_key.size() && m_to_hop.matchesKey(to_key) == false)
            {
                return false;
            }

            // Check user matches
            if (m_to_hop.user().size() && user.size())
            {
                // In original ssh this is pattern match, but for now we do exact match
                if (m_to_hop.user() != user)
                {
                    return false;
                }
            }

            if (mi.has_value())
            {
                auto &match_info = mi.value().get();
                match_info.from = m_from_hop.hostname();
                match_info.to = m_to_hop.hostname();
                match_info.user = user;
            }

            log.debug("allowed to host {}", m_to_hop.hostname());

            return true;
        }

        OpenSSHSRestrictDestination::OpenSSHSRestrictDestination() : LogEnabler("OpenSSHSRestrictDestination")
        {
            log.vdebug("OpenSSHSRestrictDestination extension created");
        }

        void OpenSSHSRestrictDestination::serialize(Serializer &s) const
        {
            Serializer out;
            for (const auto &c : m_constraints)
            {
                auto cb = c.serialize();
                out.writeBlob(cb);
            }
            s.writeBlob(out.data());
        }

        void OpenSSHSRestrictDestination::deserialize(Deserializer &d)
        {
            auto data = d.readBlob();

            Deserializer dd(data);
            do
            {
                auto b = dd.readBlob();
                m_constraints.emplace_back(b);
            } while (dd.remaining() > 0);
        }

    } // namespace libssha
} // namespace nglab