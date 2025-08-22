#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>
#include "bitcoin_key_utils.h"
using namespace BitcoinKeyUtils;

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

std::string BytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (auto b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

int main(int argc, char* argv[]) {
    // Default keys
    std::string privHex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
    std::string pubHexCom = "02D0DE0AAEAEFAD02B8BDC8A01A1B8B11C696BD3D66A2C5F10780D95B7DF42645C";

    // Check command-line arguments
    if (argc > 1 && std::string(argv[1]).length() > 0) {
        privHex = argv[1];
    }
    if (argc > 2 && std::string(argv[2]).length() > 0) {
        pubHexCom = argv[2];
    }

    // Validate and convert keys
    std::vector<uint8_t> privateKey, pubKey;
    try {
        privateKey = HexToBytes(privHex);
        pubKey = HexToBytes(pubHexCom);
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    // Set output formatting
    std::cout << std::left; // Left-align output
    const int labelWidth = 40; // Width for labels
    const int valueWidth = 66; // Width for values (accommodates long addresses)
    std::cout << std::endl;
    
    std::cout << std::setw(labelWidth) << "Private Key (Hex):"
              << std::setw(valueWidth) << BytesToHex(privateKey) << std::endl;
    std::cout << std::setw(labelWidth) << "Public Key (Compressed, Hex):"
              << std::setw(valueWidth) << BytesToHex(pubKey) << std::endl;

    auto wifCompressed = EncodeWIF(privateKey, true);
    if (wifCompressed) {
        std::cout << std::setw(labelWidth) << "WIF (Compressed):"
                  << std::setw(valueWidth) << *wifCompressed << std::endl;
    } else {
        std::cerr << std::setw(labelWidth) << "ERROR (WIF Compressed):"
                  << wifCompressed.error().message << std::endl;
    }

    auto wifUncompressed = EncodeWIF(privateKey, false);
    if (wifUncompressed) {
        std::cout << std::setw(labelWidth) << "WIF (Uncompressed):"
                  << std::setw(valueWidth) << *wifUncompressed << std::endl;
    } else {
        std::cerr << std::setw(labelWidth) << "ERROR (WIF Uncompressed):"
                  << wifUncompressed.error().message << std::endl;
    }

    auto pubKeyHashExp = HashRIPEMD160SHA256(pubKey);
    if (!pubKeyHashExp) {
        std::cerr << std::setw(labelWidth) << "ERROR (Hash160):"
                  << pubKeyHashExp.error().message << std::endl;
        return 1;
    }
    auto pubKeyHash = *pubKeyHashExp;
    std::cout << std::setw(labelWidth) << "Public Key Hash (RIPEMD160-SHA256):"
              << std::setw(valueWidth) << BytesToHex(pubKeyHash) << std::endl;

    auto p2pkh = GenerateP2PKHAddress(pubKeyHash);
    if (p2pkh) {
        std::cout << std::setw(labelWidth) << "P2PKH Address (Base58Check):"
                  << std::setw(valueWidth) << *p2pkh << std::endl;
    } else {
        std::cerr << std::setw(labelWidth) << "ERROR (P2PKH Address):"
                  << p2pkh.error().message << std::endl;
    }

    auto p2wpkh = GenerateP2WPKHAddress(pubKeyHash);
    if (p2wpkh) {
        std::cout << std::setw(labelWidth) << "P2WPKH Address (Bech32):"
                  << std::setw(valueWidth) << *p2wpkh << std::endl;
    } else {
        std::cerr << std::setw(labelWidth) << "ERROR (P2WPKH Address):"
                  << p2wpkh.error().message << std::endl;
    }

    return 0;
}
