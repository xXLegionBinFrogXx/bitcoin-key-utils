#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "bitcoin_key_utils.h"
#include "base58.h"
#include "bech32.h"

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

std::string HexFromBytes(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
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

    auto pk4 = HexToBytes("4f60fb48b2419f2e52332d00ef86923c");
    auto wif4 = BitcoinKeyUtils::EncodeWIF(pk4, true);
    REQUIRE(!wif4.has_value());
    CHECK_EQ(wif4.error().code, BitcoinKeyUtils::ErrorCode::InvalidPrivateKeySize);

}

TEST_CASE("DecodeWIF know vectors"){

    auto wif1 = "L1VUUocWhhKU2cFaHw9JLjzpCbnMwPRmf3FvmCFb3TZhHEiBkmQf";
    auto result1 = BitcoinKeyUtils::DecodeWIF(wif1);
    REQUIRE(result1.has_value());
    CHECK_EQ(HexFromBytes(result1->first), "7f7583a17e617ff534c245f38af4f67312628e8508da78201047473f39c9ebf3");
    CHECK_EQ(result1->second, true);

    // compressed = false
    auto wif2 = "5KKvtwcZrMNjbJv9Q6YM5Wo78KKdvn32tvx2kqz5oATFSLMvqCc";
    auto result2 = BitcoinKeyUtils::DecodeWIF(wif2);
    REQUIRE(result2.has_value());
    CHECK_EQ(HexFromBytes(result2->first), "c70145adffa528434a000c56cca3f5b6b91264f6e44f13752b97d473a1870a80");
    CHECK_EQ(result2->second, false);

    //testnet
    auto wif3 = "91dfcpRP4MS9jebKKaqLwVTM9xa3SK93stmvYPkSKej4DymAXXK";
    auto result3 = BitcoinKeyUtils::DecodeWIF(wif3);
    REQUIRE(!result3.has_value());
    CHECK_EQ(result3.error().code, BitcoinKeyUtils::ErrorCode::InvalidNetworkPrefix);
    
    //incorrect wif
    auto wif4 = "5Hs335bqU9N1mb62hEwS4tuPWJDLH9brXwuyTmPvyuz1StBzsBD";
    auto result4 = BitcoinKeyUtils::DecodeWIF(wif4);
    REQUIRE(!result4.has_value());
    CHECK_EQ(result4.error().code, BitcoinKeyUtils::ErrorCode::Base58CheckDecodingFailed);

    auto wif5 = "KwDiBf89QgGbjEhKnhX";
    auto result5 = BitcoinKeyUtils::DecodeWIF(wif5);
    REQUIRE(!result5.has_value());
    CHECK_EQ(result5.error().code, BitcoinKeyUtils::ErrorCode::Base58CheckDecodingFailed);

    auto wif6 = "L1VUUocWhhKU2cFaHw9JLjzpCbnMwPRmf3FvmCFb3TZhHEiBkmQ=";
    auto result6 = BitcoinKeyUtils::DecodeWIF(wif6);
    REQUIRE(!result6.has_value());
    CHECK_EQ(result6.error().code, BitcoinKeyUtils::ErrorCode::Base58CheckDecodingFailed);

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

TEST_CASE("BIP-173: uppercase valid, mixed-case invalid (decoder behavior)") {
    // Valid: all-uppercase Segwit v0 P2WPKH (BIP-173 test vector)
    {
        const std::string addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        auto dec = bech32::Decode(addr);  // your bech32 lib may return an optional/struct/tuple
        // The following checks are indicative; adapt to your bech32 API.
        CHECK(dec.encoding == bech32::Encoding::BECH32);   // version 0 uses BECH32, not BECH32m
        CHECK(dec.hrp == "bc");                            // many decoders normalize HRP to lowercase
        CHECK_FALSE(dec.data.empty());
        // First data value is witness version (0..16); for this vector it's 0
        CHECK(dec.data.front() == 0);
    }

    // Invalid: mixed-case MUST be rejected (BIP-173 test vector)
    {
        const std::string mixed = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7";
        auto dec = bech32::Decode(mixed);
        CHECK(dec.encoding == bech32::Encoding::INVALID);  
    }
}
