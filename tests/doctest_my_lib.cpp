#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "bitcoin_key_utils.h"

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        throw std::invalid_argument("Invalid hex character");
    };

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexVal(hex[i]);
        int lo = hexVal(hex[i + 1]);
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return bytes;
}

TEST_CASE("convert round-trip") {
  std::array<uint8_t, 7> src{0,1,2,3,4,5,6};
  auto vec = BitcoinKeyUtils::ConvertToByteVector(src);
  std::array<uint8_t, 7> out{};
  BitcoinKeyUtils::ConvertFromByteVector(vec, out);
  CHECK(std::equal(src.begin(), src.end(), out.begin(), out.end()));
}

TEST_CASE("EncodeWIF invalid size") {
  std::vector<uint8_t> pk(31, 0x00);
  auto w = BitcoinKeyUtils::EncodeWIF(pk, false);
  REQUIRE_FALSE(w.has_value());
  CHECK(w.error().code == BitcoinKeyUtils::ErrorCode::InvalidPrivateKeySize);
}



TEST_CASE("EncodeWIF known vectors") {
    auto pk1 = HexToBytes("9c58b927efdd901b4c592437acbf9d3129d6f00e80b3e91f76e5a8c8fbfd5fcb");
    auto wif1 = BitcoinKeyUtils::EncodeWIF(pk1, true);
    REQUIRE(wif1.has_value());
    CHECK_EQ(*wif1, "L2TdPVfgU96xSEEEu5iMe8Xe9zwk9q2iAWnBSrTygCTa8gaA8cZx");

    auto pk2 = HexToBytes("0f12ecac4f2dbc65ab6b6572d54e2d74f79896d1d53bd9282577a4f63ffdfae6");
    auto wif2 = BitcoinKeyUtils::EncodeWIF(pk2, true);
    REQUIRE(wif2.has_value());
    CHECK_EQ(*wif2, "Kwj1ghs3k5PRiGDAhNDn1dY623CULqvsnQSB4c3DcTgTfp7E9Hjw");

    auto pk3 = HexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    auto wif3 = BitcoinKeyUtils::EncodeWIF(pk3, true);
    REQUIRE(wif3.has_value());
    CHECK_EQ(*wif3, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73Nd2Mcv1");
}


TEST_CASE("HashRIPEMD160(SHA256) known vectors") {
    struct Vec { std::string pubkey_hex; std::string expected_hash160_hex; };
    const std::vector<Vec> cases = {
        {
            "0250813b74c125222305afc30d25a006062a6669dba9e798208dbf4ae816fdda14",
            "b6e4c3f1f275383cb68476e7fae11496aed97c7a"
        },
        {
            "02f09541e26ba48d52dee7010fe29f281de6588028cbc90d42a1a5d36a3a817d39",
            "a6bd6514b14a31373d1a85d6978ad6f349764d91"
        }
    };

    for (auto& v : cases) {
        auto pubkey = HexToBytes(v.pubkey_hex);
        auto expected = HexToBytes(v.expected_hash160_hex);

        auto result = BitcoinKeyUtils::HashRIPEMD160SHA256(pubkey);
        REQUIRE(result.has_value());
        CHECK(result->size() == expected.size());
        CHECK(std::equal(result->begin(), result->end(), expected.begin()));
    }
}


TEST_CASE("P2PKH / P2WPKH addresses from known pubkey hashes") {
    struct AddrVec { std::string hash160_hex; std::string expected_p2pkh; std::string expected_p2wpkh; };
    const std::vector<AddrVec> cases = {
        {
            "1eecd461605c6e927ab131bb19e2500ade0b9513",
            "13pWyxxRxoZrKpRqQXXwrKfrzAWxGoS7mQ",     // expected P2PKH
            "bc1qrmkdgctqt3hfy743xxa3ncjspt0qh9gnmw8v5j" // expected P2WPKH
        },
        {
            "99068a4c7a61976a2e52384eac2155e1bf859c8a",
            "1Ex8DmqvYNLRyUvsikZeS8uPzjTY7RHWve",     // expected P2PKH
            "bc1qnyrg5nr6vxtk5tjj8p82cg24uxlct8y2zkvhna" // expected P2WPKH
        }
    };

    for (auto& v : cases) {
        auto h160 = HexToBytes(v.hash160_hex);

        auto p2pkh = BitcoinKeyUtils::GenerateP2PKHAddress(h160);
        REQUIRE(p2pkh.has_value());
        CHECK_EQ(*p2pkh, v.expected_p2pkh);

        auto p2wpkh = BitcoinKeyUtils::GenerateP2WPKHAddress(h160, "bc");
        REQUIRE(p2wpkh.has_value());
        CHECK_EQ(*p2wpkh, v.expected_p2wpkh);
    }
}