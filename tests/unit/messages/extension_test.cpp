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
#include <libssha/messages/extension.h>
#include <libssha/extensions/extension.h>
#include <libssha/extensions/extension-factory.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <memory>
#include <string>
#include <vector>

using namespace nglab::libssha;

// Dummy extension for testing
class DummyExtension : public ExtensionBase {
public:
    DummyExtension() : ExtensionBase() {}
    void serialize(Serializer &s) const override {
        s.writeString(data);
    }
    void deserialize(Deserializer &d) override {
        data = d.readString();
    }
    std::string data = "dummy";
};

// Register dummy extension type for tests
namespace {
const char dummy_ext_name[] = "dummy-ext";
struct DummyExtensionRegistration {
    DummyExtensionRegistration() {
        ExtensionFactory::registerMessageExtension(
            dummy_ext_name,
            []() -> std::shared_ptr<ExtensionBase> {
                return std::make_shared<DummyExtension>();
            }
        );
    }
} dummy_extension_registration;
}

TEST(ExtensionMessageTest, DefaultConstructor) {
    ExtensionMessage msg;
    EXPECT_EQ(msg.type(), SSH_AGENTC_EXTENSION);
    EXPECT_TRUE(msg.extensionName().empty());
    EXPECT_EQ(msg.extension(), nullptr);
}

TEST(ExtensionMessageTest, SetAndGetExtension) {
    ExtensionMessage msg;
    auto ext = std::make_shared<DummyExtension>();
    msg.setExtension("dummy-ext", ext);
    EXPECT_EQ(msg.extensionName(), "dummy-ext");
    EXPECT_EQ(msg.extension(), ext);
}

TEST(ExtensionMessageTest, SerializeDeserializeRoundTrip) {
    ExtensionMessage msg;
    auto ext = std::make_shared<DummyExtension>();
    ext->data = "hello";
    msg.setExtension("dummy-ext", ext);

    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    ExtensionMessage msg2(base_msg);

    EXPECT_EQ(msg2.extensionName(), "dummy-ext");
    auto ext2 = std::dynamic_pointer_cast<DummyExtension>(msg2.extension());
    ASSERT_TRUE(ext2 != nullptr);
    EXPECT_EQ(ext2->data, "hello");
}

TEST(ExtensionMessageTest, ConstructFromMessageWorks) {
    ExtensionMessage msg;
    auto ext = std::make_shared<DummyExtension>();
    ext->data = "abc";
    msg.setExtension("dummy-ext", ext);
    auto data = msg.serialize();

    Message base_msg(data.data(), data.size());
    ExtensionMessage parsed(base_msg);
    EXPECT_EQ(parsed.type(), SSH_AGENTC_EXTENSION);
    EXPECT_EQ(parsed.extensionName(), "dummy-ext");
    auto ext2 = std::dynamic_pointer_cast<DummyExtension>(parsed.extension());
    ASSERT_TRUE(ext2 != nullptr);
    EXPECT_EQ(ext2->data, "abc");
}

TEST(ExtensionMessageTest, ConstructFromMessageWrongTypeThrows) {
    Serializer s;
    s.writeByte(0xFF); // Wrong type
    s.writeString("dummy-ext");
    s.finalize();
    Message wrong_msg(s.dataSecure().data(), s.dataSecure().size());
    EXPECT_THROW(ExtensionMessage parsed(wrong_msg), std::runtime_error);
}

TEST(ExtensionMessageTest, ConstructFromMessageNoDataThrows) {
    Message empty_msg({0x00, 0x00, 0x00, 0x01, SSH_AGENTC_EXTENSION}); // Message with no data
    EXPECT_THROW(ExtensionMessage parsed(empty_msg), std::runtime_error);
}
