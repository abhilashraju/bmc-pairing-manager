#pragma once
#include "cert_generator.hpp"

#include <iomanip>
#include <sstream>

using namespace NSNAME;
using EVP_MD_CTX_Ptr = openssl_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;
inline EVP_MD_CTX_Ptr makeEVPMDCTXPtr(EVP_MD_CTX* ptr)
{
    return {ptr, &EVP_MD_CTX_free};
}
std::string getExecutableMeasurement(const std::string& exePath,
                                     const EVP_PKEYPtr& privKey)
{
    // Open the executable file
    std::ifstream file(exePath, std::ios::binary);
    if (!file)
        return {};

    // Read the entire file into a buffer
    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());

    // Sign the file using EVP_DigestSign* APIs
    std::string signature;
    auto mdctx = makeEVPMDCTXPtr(EVP_MD_CTX_new());
    if (!mdctx)
    {
        return {};
    }

    if (EVP_DigestSignInit(mdctx.get(), nullptr, EVP_sha256(), nullptr,
                           privKey.get()) == 1)
    {
        if (EVP_DigestSignUpdate(mdctx.get(), fileData.data(),
                                 fileData.size()) == 1)
        {
            size_t sigLen = 0;
            if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sigLen) == 1)
            {
                std::vector<unsigned char> sig(sigLen);
                if (EVP_DigestSignFinal(mdctx.get(), sig.data(), &sigLen) == 1)
                {
                    std::ostringstream oss;
                    for (size_t i = 0; i < sigLen; ++i)
                    {
                        oss << std::hex << std::setw(2) << std::setfill('0')
                            << static_cast<int>(sig[i]);
                    }
                    signature = oss.str();
                }
            }
        }
    }
    return signature;
}
bool verifyExecutableMeasurement(const std::string& exePath,
                                 const EVP_PKEYPtr& pubKey,
                                 const std::string& signatureHex)
{
    // Open the executable file
    std::ifstream file(exePath, std::ios::binary);
    if (!file)
        return false;

    // Read the entire file into a buffer
    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());

    // Convert hex signature to binary
    if (signatureHex.length() % 2 != 0)
        return false;
    std::vector<unsigned char> signature(signatureHex.length() / 2);
    const char* hex = signatureHex.data();
    for (unsigned char& b : signature)
    {
        unsigned int byte = 0;
        std::istringstream iss(std::string(hex, 2));
        iss >> std::hex >> byte;
        b = static_cast<unsigned char>(byte);
        hex += 2; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Use EVP_DigestVerify* APIs to verify the signature
    auto mdctx = makeEVPMDCTXPtr(EVP_MD_CTX_new());
    if (!mdctx)
    {
        return false;
    }

    bool result = false;
    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sha256(), nullptr,
                             pubKey.get()) == 1)
    {
        if (EVP_DigestVerifyUpdate(mdctx.get(), fileData.data(),
                                   fileData.size()) == 1)
        {
            if (EVP_DigestVerifyFinal(mdctx.get(), signature.data(),
                                      signature.size()) == 1)
            {
                result = true;
            }
        }
    }
    return result;
}
struct MeasurementTaker
{
    EVP_PKEYPtr privkey;
    explicit MeasurementTaker(EVP_PKEYPtr pKey) : privkey(std::move(pKey)) {}
    std::string operator()(const std::string& exePath)
    {
        return getExecutableMeasurement(exePath, privkey);
    }
};
struct MeasurementVerifier
{
    EVP_PKEYPtr pubkey;
    explicit MeasurementVerifier(EVP_PKEYPtr pKey) : pubkey(std::move(pKey)) {}
    bool operator()(const std::string& exePath, const std::string& measurement)
    {
        return verifyExecutableMeasurement(exePath, pubkey, measurement);
    }
};
