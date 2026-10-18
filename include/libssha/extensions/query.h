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
#include <libssha/extensions/extension.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>

namespace nglab
{
    namespace libssha
    {
        inline constexpr char query_ext_name[] = "query";

        /**
         * @brief The "query" extension, RFC 9987 section 5.8.1.
         *
         * The request has no contents. The reply, a list of the supported
         * extension names, is built by Session as it depends on the registered extensions.
         */
        class QueryExtension : public Extension<QueryExtension,
                                                query_ext_name,
                                                ExtensionType::MessageExtension>
        {
        public:
            virtual void serialize(Serializer &s) const override;
            /**
             * @brief Check that the request has no contents
             * @throws std::runtime_error if there is any data left
             */
            virtual void deserialize(Deserializer &d) override;
        };
    } // namespace libssha
} // namespace nglab
