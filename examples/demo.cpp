#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include "bitcoin_key_utils.h"

using namespace BitcoinKeyUtils;

std::vector<uint8_t> HexToBytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string BytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (auto b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

int main() {
    // Private key from user
    std::string privHex     = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
    std::string pubHexCom   = "02D0DE0AAEAEFAD02B8BDC8A01A1B8B11C696BD3D66A2C5F10780D95B7DF42645C";
    auto privateKey = HexToBytes(privHex);
    auto pubKey = HexToBytes(pubHexCom);

    std::cout << "Private Key (hex): " << BytesToHex(privateKey) << std::endl;
    std::cout << "Public Key Compressed (hex): " << BytesToHex(pubKey) << std::endl;

    // Encode WIF (compressed = true)
    // KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
    auto wifCompressed = EncodeWIF(privateKey, true);
    if (wifCompressed) {
        std::cout << "WIF (compressed): " << *wifCompressed << std::endl;
    } else {
        std::cerr << "WIF encoding failed: " << wifCompressed.error().message << std::endl;
    }

    // 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
    auto wifUncompressed = EncodeWIF(privateKey, false);
    if (wifUncompressed) {
        std::cout << "WIF (uncompressed): " << *wifUncompressed << std::endl;
    } else {
        std::cerr << "WIF encoding failed: " << wifUncompressed.error().message << std::endl;
    }

    auto pubKeyHashExp = HashRIPEMD160SHA256(pubKey);
    if (!pubKeyHashExp) {
        std::cerr << "Hash160 failed: " << pubKeyHashExp.error().message << std::endl;
        return 1;
    }

    // HAS160 d9351dcbad5b8f3b8bfa2f2cdc85c28118ca9326
    auto pubKeyHash = *pubKeyHashExp;
    std::cout << "PubKey HASH160 (hex): " << BytesToHex(pubKeyHash) << std::endl;

    // P2PKH address (Base58Check)
    // 1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK
    auto p2pkh = GenerateP2PKHAddress(pubKeyHash);
    if (p2pkh) {
        std::cout << "P2PKH address: " << *p2pkh << std::endl;
    } else {
        std::cerr << "P2PKH address generation failed: " << p2pkh.error().message << std::endl;
    }

    // SegWit P2WPKH address (Bech32)
    // bc1qmy63mjadtw8nhzl69ukdepwzsyvv4yex5qlmkd
    auto p2wpkh = GenerateP2WPKHAddress(pubKeyHash);
    if (p2wpkh) {
        std::cout << "P2WPKH (bech32) address: " << *p2wpkh << std::endl;
    } else {
        std::cerr << "P2WPKH address generation failed: " << p2wpkh.error().message << std::endl;
    }


    return 0;
}
