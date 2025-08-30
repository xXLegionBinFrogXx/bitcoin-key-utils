#include "bitcoin_key_utils.h"
#include <cstring>
#include <stdexcept>
#include "base58.h"
#include "bech32.h"
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"
#include "util/strencodings.h"

namespace BitcoinKeyUtils {

std::expected<std::string, Error> EncodeWIF(const std::vector<uint8_t>& privateKey,bool compressed) {
    if (privateKey.size() != Constants::PrivateKeySize) {
        return std::unexpected(Error{ErrorCode::InvalidPrivateKeySize, "Invalid private key size for WIF encoding: " + std::to_string(privateKey.size()) +", expected: " + std::to_string(Constants::PrivateKeySize)});
    }

    std::vector<uint8_t> data;
    data.push_back(Constants::MainNet);
    data.insert(data.end(), privateKey.begin(), privateKey.end());
    if (compressed) {
        data.push_back(Constants::CompressMagic);
    }

    std::string wifString = EncodeBase58Check(data);
    if (wifString.empty()) {
        return std::unexpected(Error{ErrorCode::Base58CheckEncodingFailed, "Base58Check encoding fail !"});
    }

    return wifString;
}

std::expected<std::pair<std::vector<uint8_t>, bool>, Error> DecodeWIF(const std::string& wifString) {
    std::vector<uint8_t> decoded;
    constexpr int max_ret_len = Constants::PrivateKeySize + 5;

    if (!DecodeBase58Check(wifString.c_str(), decoded, max_ret_len)) {
        return std::unexpected(Error{ErrorCode::Base58CheckDecodingFailed, "Base58Check decoding failed"});
    }

    if (decoded.size() < Constants::PrivateKeySize + 1) {
        return std::unexpected(Error{ErrorCode::InvalidWIFLength, 
            "Invalid WIF decoded length: " + std::to_string(decoded.size()) + 
            ", expected at least: " + std::to_string(Constants::PrivateKeySize + 1)});
    }

    if (decoded[0] != Constants::MainNet) {
        return std::unexpected(Error{ErrorCode::InvalidNetworkPrefix, 
            "Invalid network prefix: " + std::to_string(decoded[0]) + 
            ", expected: " + std::to_string(Constants::MainNet)});
    }

    bool compressed = false;
    size_t expectedSize = Constants::PrivateKeySize + 1;
    if (decoded.size() == expectedSize + 1) {
        if (decoded.back() == Constants::CompressMagic) {
            compressed = true;
        } else {
            return std::unexpected(Error{ErrorCode::InvalidCompressionFlag, 
                "Invalid compression flag: " + std::to_string(decoded.back())});
        }
    } else if (decoded.size() != expectedSize) {
        return std::unexpected(Error{ErrorCode::InvalidWIFLength,"Invalid WIF decoded length: " + std::to_string(decoded.size()) + 
            ", expected: " + std::to_string(expectedSize) + " or " + std::to_string(expectedSize + 1)});
    }

    std::vector<uint8_t> privateKey(decoded.begin() + 1, decoded.begin() + 1 + Constants::PrivateKeySize);
    
    return std::make_pair(privateKey, compressed);
}


std::expected<std::vector<uint8_t>, Error> HashRIPEMD160SHA256(const std::vector<uint8_t>& data) {

    if (data.empty()) {
        return std::unexpected(Error{ErrorCode::EmptyData, "Cannot hash empty data"});
    }

    CSHA256 sha256;
    sha256.Write(data.data(), data.size());
    std::vector<uint8_t> sha256_result(CSHA256::OUTPUT_SIZE);
    sha256.Finalize(sha256_result.data());

    CRIPEMD160 ripemd160;
    ripemd160.Write(sha256_result.data(), CSHA256::OUTPUT_SIZE);
    std::vector<uint8_t> ripemd160_result(CRIPEMD160::OUTPUT_SIZE);
    ripemd160.Finalize(ripemd160_result.data());

    if (ripemd160_result.size() != Constants::Hash160Size) {
        return std::unexpected(Error{ErrorCode::Hash160SizeMismatch, "Hash160 result size mismatch: " + std::to_string(ripemd160_result.size()) +", expected: " + std::to_string(Constants::Hash160Size)});
    }
    
    return ripemd160_result;
}

std::expected<std::string, Error> GenerateP2PKHAddress(const std::vector<uint8_t>& pubKeyHash) {
    if (pubKeyHash.size() != Constants::Hash160Size) {
        return std::unexpected(Error{ErrorCode::InvalidPubKeyHashSize,"Invalid pubKeyHash size for P2PKH: " + std::to_string(pubKeyHash.size()) +", expected: " + std::to_string(Constants::Hash160Size)});
    }

    std::vector<uint8_t> data;
    data.push_back(Constants::P2PKHPrefix);
    data.insert(data.end(), pubKeyHash.begin(), pubKeyHash.end());
    std::string address = EncodeBase58Check(data);

    if (address.empty()) {
        return std::unexpected(Error{ErrorCode::Base58CheckEncodingFailed,"Base58Check encoding failed for P2PKH address"});
    }
    return address;
}

std::expected<std::string, Error> GenerateP2WPKHAddress(const std::vector<uint8_t>& pubKeyHash, std::string_view hrp) {
    if (pubKeyHash.size() != Constants::Hash160Size) {
        return std::unexpected(Error{ErrorCode::InvalidPubKeyHashSize, "Invalid pubKeyHash size: " + std::to_string(pubKeyHash.size()) +", expected: " + std::to_string(Constants::Hash160Size)});
    }

    if (hrp.empty() || hrp.length() > 83) {
        return std::unexpected(Error{ErrorCode::InvalidHRP, "Invalid HRP for Bech32 encoding: empty or too long"});
    }

      // Reject mixed-case input (decoder MUST reject mixed-case per BIP-173)
    bool hasLower = std::any_of(hrp.begin(), hrp.end(), [](unsigned char c){ return std::islower(c); });
    bool hasUpper = std::any_of(hrp.begin(), hrp.end(), [](unsigned char c){ return std::isupper(c); });
    if (hasLower && hasUpper) {
        return std::unexpected(Error{ErrorCode::InvalidHRP, "Mixed-case HRP not allowed"});
    }

    // Normalize to lowercase for encoding (encoders MUST output lowercase)
    std::string hrp_lc;
    hrp_lc.reserve(hrp.size());
    for (unsigned char c : hrp) {
        if (c < 33 || c > 126) { // printable US-ASCII only
            return std::unexpected(Error{ErrorCode::InvalidHRP, "HRP contains non-printable ASCII"});
        }
        hrp_lc.push_back(static_cast<char>(std::tolower(c)));
    }

        // If this function is specifically for Segwit v0 addresses, enforce network HRP:
    if (!(hrp_lc == "bc" || hrp_lc == "tb")) {
        return std::unexpected(Error{ErrorCode::InvalidHRP, "Segwit v0 HRP must be 'bc' or 'tb'"});
    }

    std::vector<uint8_t> conv_data;
    bool success = ConvertBits<8, 5, true>([&](int v) { conv_data.push_back(static_cast<uint8_t>(v)); }, pubKeyHash.begin(), pubKeyHash.end());
    if (!success) {
        return std::unexpected(Error{ErrorCode::Bech32BitConversionFailed,"Failed to convert bits for Bech32 encoding"});
    }

    if (conv_data.size() != 32) { // 160 bits / 5 bits per value = 32 values
        return std::unexpected(Error{ErrorCode::Bech32BitConversionFailed, "Invalid number of 5-bit values after conversion: " + std::to_string(conv_data.size()) + ", expected: 32"});
    }

    std::vector<uint8_t> data;
    data.push_back(Constants::WitnessVersion0); // must be integer 0, not '0'
    data.insert(data.end(), conv_data.begin(), conv_data.end());

    std::string address = bech32::Encode(bech32::Encoding::BECH32, hrp_lc, data);
    if (address.empty()) {
        return std::unexpected(Error{ErrorCode::Bech32EncodingFailed, "Bech32 encoding failed"});
    }

    return address;
}

} 

