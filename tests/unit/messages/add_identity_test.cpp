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
#include <libssha/messages/add-identity.h>
#include <libssha/messages/message.h>
#include <libssha/extensions/extension-factory.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/secure_vector.h>
#include <vector>
#include <stdexcept>

using namespace nglab::libssha;

namespace nglab::libssha::test::add_identity
{

// Message format: RFC 9987, section 5.2

TEST(AddIdentityMessage, DefaultConstructor)
{
    AddIdentityMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_ADD_IDENTITY);
    EXPECT_EQ(msg.keyType(), "");
    EXPECT_EQ(msg.keyComment(), "");
    EXPECT_TRUE(msg.keyBlob().empty());
    EXPECT_FALSE(msg.confirmRequired());
    EXPECT_EQ(msg.lifetime(), 0u);
}

TEST(AddIdentityMessage, SettersAndGetters)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("test comment");
    secure_vector<uint8_t> blob = {1, 2, 3, 4};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(true);
    msg.setLifetime(123);

    EXPECT_EQ(msg.keyType(), "ssh-ed25519");
    EXPECT_EQ(msg.keyComment(), "test comment");
    EXPECT_EQ(msg.keyBlob(), blob);
    EXPECT_TRUE(msg.confirmRequired());
    EXPECT_EQ(msg.lifetime(), 123u);
}

TEST(AddIdentityMessage, SerializeDeserializeRoundTripEd25519)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("comment");
    secure_vector<uint8_t> blob = {0x00, 0x00, 0x00, 0x02,
                                          0xAA, 0xBB,
                                          0x00, 0x00, 0x00, 0x04,
                                          0xCC, 0xDD, 0xEE, 0xFF};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(true);
    msg.setLifetime(42);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    AddIdentityMessage msg2(base_msg);

    EXPECT_EQ(msg2.keyType(), msg.keyType());
    EXPECT_EQ(msg2.keyComment(), msg.keyComment());
    EXPECT_EQ(msg2.keyBlob(), msg.keyBlob());
    EXPECT_EQ(msg2.confirmRequired(), msg.confirmRequired());
    EXPECT_EQ(msg2.lifetime(), msg.lifetime());
}

TEST(AddIdentityMessage, SerializeDeserializeRoundTripRSA)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-rsa");
    msg.setKeyComment("rsa comment");
    secure_vector<uint8_t> blob = {0x00, 0x00, 0x00, 0x03,
                                          0x11, 0x22, 0x33,
                                          0x00, 0x00, 0x00, 0x03,
                                          0x44, 0x55, 0x66,
                                          0x00, 0x00, 0x00, 0x03,
                                          0x77, 0x88, 0x99,
                                          0x00, 0x00, 0x00, 0x03,
                                          0xAA, 0xBB, 0xCC,
                                          0x00, 0x00, 0x00, 0x03,
                                          0xDD, 0xEE, 0xFF,
                                          0x00, 0x00, 0x00, 0x03,
                                          0x10, 0x20, 0x30};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(false);
    msg.setLifetime(0);

    secure_vector<uint8_t> serialized = msg.serialize();
    Message base_msg(serialized.data(), serialized.size());
    AddIdentityMessage msg2(base_msg);

    EXPECT_EQ(msg2.keyType(), msg.keyType());
    EXPECT_EQ(msg2.keyComment(), msg.keyComment());
    EXPECT_EQ(msg2.keyBlob(), msg.keyBlob());
    EXPECT_EQ(msg2.confirmRequired(), msg.confirmRequired());
    EXPECT_EQ(msg2.lifetime(), msg.lifetime());
}

TEST(AddIdentityMessage, ConstructorFromInvalidTypeThrows)
{
    std::string invalid_message_payload = {0x00, 0x00, 0x00, 0x01, 0x42}; // Length + invalid type
    Message wrong_type_msg(reinterpret_cast<const uint8_t *>(invalid_message_payload.data()), invalid_message_payload.size());
    // Set type manually if needed, or use a valid buffer with wrong type byte
    EXPECT_THROW(AddIdentityMessage msg(wrong_type_msg), std::runtime_error);
}

// RFC 9987, section 5.2: an unrecognised key type gets FAILURE
TEST(AddIdentityMessage, UnsupportedKeyTypeThrows)
{
    Serializer s;
    s.writeBE32(0); // Placeholder for length
    s.writeByte(SSH_AGENTC_ADD_IDENTITY);
    s.writeString("unsupported-key-type");
    s.writeBlob({0x10, 0x20, 0x30});
    s.writeBlob({0x40, 0x50, 0x60});
    s.writeString("comment");
    s.finalize();

    Message base_msg(s.data().data(), s.data().size());
    EXPECT_THROW(AddIdentityMessage msg(base_msg), std::runtime_error);
}

TEST(AddIdentityMessage, ContructorWithConstrains)
{
    AddIdentityMessage msg;
    msg.setKeyType("ssh-ed25519");
    msg.setKeyComment("test comment");
    secure_vector<uint8_t> blob = {1, 2, 3, 4};
    msg.setKeyBlob(blob);
    msg.setConfirmRequired(true);
    msg.setLifetime(123);

    EXPECT_EQ(msg.type(), SSH_AGENTC_ADD_IDENTITY_CONSTRAINED);
    EXPECT_EQ(msg.keyType(), "ssh-ed25519");
    EXPECT_EQ(msg.keyComment(), "test comment");
    EXPECT_EQ(msg.keyBlob(), blob);
    EXPECT_TRUE(msg.confirmRequired());
    EXPECT_EQ(msg.lifetime(), 123u);
}

    constexpr char RestrictDestinationName[] = "restrict-destination-v00@openssh.com";

    std::vector<uint8_t> hopBlob(const std::string &hostname, const std::vector<uint8_t> &key)
    {
        Serializer s;
        s.writeString("");
        s.writeString(hostname);
        s.writeBlob({}); // extensions not supported
        if (!key.empty())
        {
            s.writeBlob(key);
            s.writeByte(0);
        }
        return s.data();
    }

    // Constraint payload of restrict-destination-v00@openssh.com with one destination
    std::vector<uint8_t> restrictDestinationPayload()
    {
        Serializer constraint;
        constraint.writeBlob(hopBlob("", {}));
        constraint.writeBlob(hopBlob("host", {0x33, 0x44}));
        constraint.writeBlob({}); // extensions not supported

        Serializer list;
        list.writeBlob(constraint.data());
        return list.data();
    }

    void appendConfirm(Serializer &s) { s.writeByte(SSH_AGENT_CONSTRAIN_CONFIRM); }

    void appendLifetime(Serializer &s, uint32_t seconds)
    {
        s.writeByte(SSH_AGENT_CONSTRAIN_LIFETIME);
        s.writeBE32(seconds);
    }

    void appendRestrictDestination(Serializer &s)
    {
        s.writeByte(SSH_AGENT_CONSTRAIN_EXTENSION);
        s.writeString(RestrictDestinationName);
        s.writeBlob(restrictDestinationPayload());
    }

    // Builds a message and parses it, `constraints` fills the part after the comment
    template <typename Fn>
    void parseAddIdentity(uint8_t type, Fn constraints)
    {
        ExtensionFactory::initializeExtensions();
        Serializer s;
        s.writeBE32(0); // Placeholder for length
        s.writeByte(type);
        s.writeString("ssh-ed25519");
        s.writeBlob({0xAA, 0xBB});
        s.writeBlob({0xCC, 0xDD, 0xEE, 0xFF});
        s.writeString("comment");
        constraints(s);
        s.finalize();

        // data() returns a copy, it has to outlive the message
        const auto bytes = s.data();
        Message base_msg(bytes.data(), bytes.size());
        AddIdentityMessage msg(base_msg);
    }

// RFC 9987, section 5.2: SSH_AGENTC_ADD_IDENTITY ends with the comment, constraints need ADD_ID_CONSTRAINED
TEST(AddIdentityMessage, DataAfterCommentInPlainAddThrows)
{
    EXPECT_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY, [](Serializer &s) { appendConfirm(s); }), std::runtime_error);
    EXPECT_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY, [](Serializer &s) { s.writeByte(0); }), std::runtime_error);
}

TEST(AddIdentityMessage, PlainAddWithoutConstraintsParses)
{
    EXPECT_NO_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY, [](Serializer &) {}));
}

// Stricter than RFC 9987, section 5.2.7: a repeated constraint is refused instead of overriding the previous one
TEST(AddIdentityMessage, RepeatedConstraintsThrow)
{
    EXPECT_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, [](Serializer &s) { appendConfirm(s); appendConfirm(s); }),
                 std::runtime_error);
    EXPECT_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED, [](Serializer &s) { appendLifetime(s, 10); appendLifetime(s, 3600); }),
                 std::runtime_error);
    EXPECT_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED,
                                  [](Serializer &s) { appendRestrictDestination(s); appendRestrictDestination(s); }),
                 std::runtime_error);
}

TEST(AddIdentityMessage, EachConstraintOnceInAnyOrderParses)
{
    EXPECT_NO_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED,
                                     [](Serializer &s) { appendConfirm(s); appendLifetime(s, 60); appendRestrictDestination(s); }));
    EXPECT_NO_THROW(parseAddIdentity(SSH_AGENTC_ADD_IDENTITY_CONSTRAINED,
                                     [](Serializer &s) { appendRestrictDestination(s); appendLifetime(s, 60); appendConfirm(s); }));
}
} // namespace nglab::libssha::test::add_identity
