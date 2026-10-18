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
#include <libssha/extensions/extension-factory.h>
#include <libssha/extensions/openssh-session-bind.h>
#include <libssha/extensions/openssh-restrict-destination.h>
#include <libssha/extensions/query.h>
#include <algorithm>
namespace nglab
{
    namespace libssha
    {
        ExtensionFactory &ExtensionFactory::instance()
        {
            static ExtensionFactory instance;
            return instance;
        }

        void ExtensionFactory::registerMessageExtension(const std::string &ext_name, ExtensionCreatorFunc creator)
        {
            instance().m_message_extension_creators[ext_name] = creator;
        }

        void ExtensionFactory::registerConstraintExtension(const std::string &ext_name, ExtensionCreatorFunc creator)
        {
            instance().m_constraint_extension_creators[ext_name] = creator;
        }

        std::shared_ptr<ExtensionBase> ExtensionFactory::createMessageExtension(const std::string &ext_name)
        {
            auto it = instance().m_message_extension_creators.find(ext_name);
            if (it != instance().m_message_extension_creators.end())
            {
                return it->second();
            }
            else
            {
                throw std::runtime_error("ExtensionFactory: unknown message extension: " + ext_name);
            }
        }

        std::shared_ptr<ExtensionBase> ExtensionFactory::createConstraintExtension(const std::string &ext_name)
        {
            auto it = instance().m_constraint_extension_creators.find(ext_name);
            if (it != instance().m_constraint_extension_creators.end())
            {
                return it->second();
            }
            else
            {
                throw std::runtime_error("ExtensionFactory: unknown constraint extension: " + ext_name);
            }
        }

        bool ExtensionFactory::isMessageExtension(const std::string &ext_name)
        {
            const auto &creators = instance().m_message_extension_creators;
            return creators.find(ext_name) != creators.end();
        }

        std::vector<std::string> ExtensionFactory::extensionNames()
        {
            std::vector<std::string> names;
            for (const auto &entry : instance().m_message_extension_creators)
            {
                names.push_back(entry.first);
            }
            for (const auto &entry : instance().m_constraint_extension_creators)
            {
                names.push_back(entry.first);
            }
            std::sort(names.begin(), names.end());
            names.erase(std::unique(names.begin(), names.end()), names.end());
            return names;
        }

        void ExtensionFactory::initializeExtensions()
        {
            QueryExtension::registerType();
            OpenSSHSessionBind::registerType();
            OpenSSHSRestrictDestination::registerType();
        }
    }
}