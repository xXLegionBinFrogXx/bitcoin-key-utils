#pragma once

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>       

namespace BitcoinKeyUtils {

namespace Constants {
    inline constexpr uint8_t MainNet = 0x80;
    inline constexpr uint8_t CompressMagic = 0x01;
    inline constexpr uint8_t P2PKHPrefix = 0x00;
    inline constexpr uint8_t WitnessVersion0 = 0x00;
    inline constexpr int PrivateKeySize = 32;
    inline constexpr int Hash160Size = 20;
    inline constexpr std::string_view Bech32MainnetHRP = "bc";
}

enum class ErrorCode {
    InvalidPrivateKeySize,
    Base58CheckEncodingFailed,
    EmptyData,
    Hash160SizeMismatch,
    InvalidPubKeyHashSize,
    InvalidHRP,
    Bech32BitConversionFailed,
    Bech32EncodingFailed
};

struct Error {
    ErrorCode code;
    std::string message;
};

/**
 * @brief Converts raw data into a vector of bytes.
 * @param data Input data as span of bytes.
 * @return A vector of bytes.
 */
std::vector<uint8_t> ConvertToByteVector(std::span<const uint8_t> data);

/**
 * @brief Converts a vector of bytes into raw data.
 * @param data Input vector of bytes.
 * @param output Output span where the bytes will be copied.
 * @throw std::length_error if output span is too small.
 */
void ConvertFromByteVector(const std::vector<uint8_t>& data, std::span<uint8_t> output);

/**
 * @brief Encode a private key into Wallet Import Format (WIF).
 * @param privateKey 32-byte private key.
 * @param compressed Flag to indicate if the key is compressed (or not ).
 * @return WIF string on success, otherwise an Error.
 */
std::expected<std::string, Error> EncodeWIF(const std::vector<uint8_t>& privateKey, bool compressed);

/**
 * @brief Compute SHA256 followed by RIPEMD160 hash of input data.
 * @param data Input data vector.
 * @return The 20-byte Hash160 if succesful, otherwise Error.
 */
std::expected<std::vector<uint8_t>, Error> HashRIPEMD160SHA256(const std::vector<uint8_t>& data);

/**
 * @brief Generate a P2PKH (legacy) Bitcoin address from a public key hash.
 * @param pubKeyHash 20-byte public key hash.
 * @return The P2PKH address string if succesful, otherwise Error.
 */
std::expected<std::string, Error> GenerateP2PKHAddress(const std::vector<uint8_t>& pubKeyHash);

/**
 * @brief Generate a P2WPKH (SegWit) Bitcoin address from a public key hash.
 * @param pubKeyHash 20-byte public key hash.
 * @param hrp Human-readable prefix (default: "bc").
 * @return The Bech32 encoded address string if succesfull, otherwise Error.
 */
std::expected<std::string, Error> GenerateP2WPKHAddress(const std::vector<uint8_t>& pubKeyHash, std::string_view hrp =Constants::Bech32MainnetHRP);

}

