#include "bitcoin_key_utils.h"
#include <cstring>

#include "base58.h"
#include "bech32.h"
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"
#include "util/strencodings.h"

namespace BitcoinKeyUtils {

std::vector<uint8_t> ConvertToByteVector(std::span<const uint8_t> data) {
    return std::vector<uint8_t>(data.begin(), data.end());
}

//TODO : improve this method
void ConvertFromByteVector(const std::vector<uint8_t>& data, std::span<uint8_t> output) {
    if (output.size() < data.size()) {
        throw std::length_error("Output span is too small");
    }
    std::memcpy(output.data(), data.data(), data.size());
}

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

    for (char c : hrp) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
            return std::unexpected(Error{ErrorCode::InvalidHRP,"Invalid HRP contains forbidden characters: " + std::string(hrp)});
        }
    }

    std::vector<uint8_t> conv_data;
    bool success = ConvertBits<8, 5, true>([&](int v) { conv_data.push_back(static_cast<uint8_t>(v)); }, pubKeyHash.begin(), pubKeyHash.end());
    if (!success) {
        return std::unexpected(Error{ErrorCode::Bech32BitConversionFailed,"Failed to convert bits for Bech32 encoding"});
    }

    std::vector<uint8_t> data;
    data.push_back(Constants::WitnessVersion0);
    data.insert(data.end(), conv_data.begin(), conv_data.end());
    std::string address = bech32::Encode(bech32::Encoding::BECH32, std::string(hrp), data);

    if (address.empty()) {
        return std::unexpected(Error{ErrorCode::Bech32EncodingFailed,"Failed to encode Bech32 address"});
    }

    return address;
}

} 

