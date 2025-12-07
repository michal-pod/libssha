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
#include <libssha/extensions/openssh-session-bind.h>
#include <libssha/utils/serializer.h>
#include <libssha/utils/deserializer.h>
#include <libssha/key/key-factory.h>
#include <libssha/key/pub-key.h>
#include <string>
#include <vector>

using namespace nglab::libssha;

namespace {

class DummyPubKey : public PubKeyBase {
public:
    DummyPubKey(const std::vector<uint8_t>& blob) : PubKeyBase(blob) {}
    std::string fingerprint([[maybe_unused]] FingerprintFormat format = FingerprintFormat::Sha256Base64) const override { return "dummy-fingerprint"; }
    std::vector<std::string> visualHostKey() override { return {}; }
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature) const override {
                    Deserializer sig_deser(signature);
            auto sig_type = sig_deser.readString();
            auto sig_blob = sig_deser.readBlob();
        // Accept if signature equals data
        return sig_blob == data;
    }
    size_t bits() const override { return 42; }
    std::string family() const override { return "DUMMY"; }
};

constexpr const char dummy_type_name[] = "dummy-type";

void registerDummyPubKeyType() {
    static bool registered = false;
    if (!registered) {
        KeyFactory::registerPubKeyType(
            dummy_type_name,
            [](const std::vector<uint8_t>& blob) {
                return std::make_shared<DummyPubKey>(blob);
            }
        );
        registered = true;
    }
}

std::vector<uint8_t> makeDummyHostKeyBlob() {
    Serializer s;
    s.writeString(dummy_type_name);
    s.writeBlob({0x01, 0x02, 0x03});
    auto data = s.data();
    return std::vector<uint8_t>(data.begin(), data.end());
}

std::vector<uint8_t> makeDummySignatureBlob(const std::vector<uint8_t>& session_id) {
    Serializer s;
    s.writeString(dummy_type_name);
    s.writeBlob(session_id); // signature blob equals session_id for DummyPubKey
    auto data = s.data();
    return std::vector<uint8_t>(data.begin(), data.end());
}

} // namespace

TEST(OpenSSHSessionBindTest, ConstructionAndSetters)
{
    OpenSSHSessionBind ext;
    std::vector<uint8_t> host_key = {1,2,3};
    std::vector<uint8_t> session_id = {4,5,6};
    std::vector<uint8_t> signature = {7,8,9};
    ext.setHostKey(host_key);
    ext.setSessionID(session_id);
    ext.setSignature(signature);
    ext.setForwarded(true);

    EXPECT_EQ(ext.hostKey(), host_key);
    EXPECT_EQ(ext.sessionID(), session_id);
    EXPECT_EQ(ext.signature(), signature);
    EXPECT_TRUE(ext.forwarded());
}

TEST(OpenSSHSessionBindTest, SerializeDeserializeRoundTrip)
{
    registerDummyPubKeyType();
    OpenSSHSessionBind ext;
    std::vector<uint8_t> session_id = {0x10, 0x20, 0x30};
    ext.setHostKey(makeDummyHostKeyBlob());
    ext.setSessionID(session_id);
    ext.setSignature(makeDummySignatureBlob(session_id));
    ext.setForwarded(false);

    Serializer s;
    ext.serialize(s);
    auto data = s.data();

    OpenSSHSessionBind ext2;
    Deserializer d(data.data(), data.size());
    EXPECT_NO_THROW(ext2.deserialize(d));
    EXPECT_EQ(ext2.hostKey(), ext.hostKey());
    EXPECT_EQ(ext2.sessionID(), ext.sessionID());
    EXPECT_EQ(ext2.signature(), ext.signature());
    EXPECT_EQ(ext2.forwarded(), ext.forwarded());
}

TEST(OpenSSHSessionBindTest, DeserializeFailsOnBadSignature)
{
    registerDummyPubKeyType();
    OpenSSHSessionBind ext;
    std::vector<uint8_t> session_id = {0x10, 0x20, 0x30};
    ext.setHostKey(makeDummyHostKeyBlob());
    ext.setSessionID(session_id);
    // Signature blob does not match session_id, so DummyPubKey::verify will fail
    ext.setSignature(makeDummySignatureBlob({0x99, 0x88, 0x77}));
    ext.setForwarded(false);

    Serializer s;
    ext.serialize(s);
    auto data = s.data();

    OpenSSHSessionBind ext2;
    Deserializer d(data.data(), data.size());
    EXPECT_THROW(ext2.deserialize(d), std::runtime_error);
}
