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
#include <gtest/gtest.h>
#include <libssha/extensions/openssh-restrict-destination.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <vector>
#include <string>

using namespace nglab::libssha;

std::vector<uint8_t> makeHopDescriptorBlob(const std::string& user, const std::string& hostname, const std::vector<std::vector<uint8_t>>& keys, bool ca = false) {
    Serializer s;
    s.writeString(user);
    s.writeString(hostname);
    s.writeBlob({}); // extensions not supported
    for (const auto& key : keys) {
        s.writeBlob(key);
        s.writeByte(ca ? 1 : 0);
    }
    return s.data();
}

std::vector<uint8_t> makeDestinationConstraintBlob(
    const std::string& from_user, const std::string& from_hostname, const std::vector<std::vector<uint8_t>>& from_keys,
    const std::string& to_user, const std::string& to_hostname, const std::vector<std::vector<uint8_t>>& to_keys)
{
    Serializer s;
    s.writeBlob(makeHopDescriptorBlob(from_user, from_hostname, from_keys));
    s.writeBlob(makeHopDescriptorBlob(to_user, to_hostname, to_keys));
    s.writeBlob({}); // extensions not supported

    return s.data();
}

TEST(OpenSSHHopDescriptorTest, ConstructAndMatchesKey)
{
    std::vector<uint8_t> key1 = {0x01, 0x02};
    std::vector<uint8_t> key2 = {0x03, 0x04};
    auto blob = makeHopDescriptorBlob("", "hostA", {key1, key2});
    OpenSSHHopDescriptor hop(blob, "test");
    EXPECT_EQ(hop.hostname(), "hostA");
    EXPECT_TRUE(hop.matchesKey(key1));
    EXPECT_TRUE(hop.matchesKey(key2));
    EXPECT_FALSE(hop.matchesKey({0xFF, 0xFF}));
}

TEST(OpenSSHHopDescriptorTest, EmptyKeyIsNotMatched)
{
    auto blob = makeHopDescriptorBlob("", "hostB", {{}});
    OpenSSHHopDescriptor hop(blob, "");
    EXPECT_FALSE(hop.matchesKey({}));
}

TEST(OpenSSHSDestinationConstraintTest, ConstructAndMatches)
{
    std::vector<uint8_t> from_key = {0x11, 0x22};
    std::vector<uint8_t> to_key = {0x33, 0x44};
    auto blob = makeDestinationConstraintBlob("", "", {}, "userX", "hostY", {to_key});
    OpenSSHSDestinationConstraint constraint(blob);

    // Should match when to_key matches and user matches
    EXPECT_TRUE(constraint.matches({}, to_key, "userX"));
    // Should not match if user does not match
    EXPECT_FALSE(constraint.matches({}, to_key, "otherUser"));
    // Should not match if to_key does not match
    EXPECT_FALSE(constraint.matches({}, from_key, "userX"));
}

TEST(OpenSSHSDestinationConstraintTest, InvalidFromHopThrows)
{
    // from_hop with hostname but no keys
    auto blob = makeDestinationConstraintBlob("", "host", {}, "user", "hostY", {{0x01}});
    EXPECT_THROW(OpenSSHSDestinationConstraint constraint(blob), std::runtime_error);
}

TEST(OpenSSHSDestinationConstraintTest, InvalidToHopThrows)
{
    // to_hop with empty hostname
    auto blob = makeDestinationConstraintBlob("", "", {}, "user", "", {{0x01}});
    EXPECT_THROW(OpenSSHSDestinationConstraint constraint(blob), std::runtime_error);
}

TEST(OpenSSHSRestrictDestinationTest, DeserializeParsesConstraints)
{
    Serializer s;
    auto c1 = makeDestinationConstraintBlob("", "", {}, "userA", "hostA", {{0x01}});
    auto c2 = makeDestinationConstraintBlob("", "", {}, "userB", "hostB", {{0x02}});
    s.writeBlob(c1);
    s.writeBlob(c2);

    Serializer ext_serializer;
    auto data = s.data();
    ext_serializer.writeBlob(data);

    auto ext_data = ext_serializer.data();

    Deserializer d(ext_data);
    OpenSSHSRestrictDestination ext;
    EXPECT_NO_THROW(ext.deserialize(d));
    EXPECT_EQ(ext.constraints().size(), 2);
}
