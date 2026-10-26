#pragma once
#include "cert_generator.hpp"

#include <openssl/rand.h>

#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <tuple>
#include <utility>

namespace NSNAME
{

/**
 * @brief TPM2 Certificate Manager
 *
 * Provides functionality for loading certificates and private keys
 * from TPM2 hardware security module using OpenSSL's TPM2 provider.
 * All operations are synchronous and return boost::system::error_code.
 *
 * Note: Store operations are not supported as OpenSSL's OSSL_STORE API
 * is read-only. Use tpm2-tools directly for storing to TPM2.
 */
class Tpm2CertManager
{
  private:
    OSSL_LIB_CTX* libCtx{nullptr};
    OSSL_PROVIDER* tpmProvider{nullptr};
    OSSL_PROVIDER* defaultProvider{nullptr};
    void* tpmProviderHandle{nullptr};
    bool initialized{false};

    // TPM2 Command Templates
    static constexpr const char* TPM2_CREATE_PRIMARY_CMD =
        "tpm2_createprimary -C o -c {}";

    // ECC P-256 keys are preferred when supported by the TPM hardware.
    // If ECC is not supported (e.g. RSA-only TPM), fallback to RSA-2048.
    static constexpr const char* TPM2_CREATE_KEY_ECC_CMD =
        R"(tpm2_create -C {} -g sha256 -G ecc256 -r {} -u {} -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign")";

    static constexpr const char* TPM2_CREATE_KEY_RSA_CMD =
        R"(tpm2_create -C {} -g sha256 -G rsa2048 -r {} -u {} -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign")";

    static constexpr const char* TPM2_LOAD_KEY_CMD =
        "tpm2_load -C {} -r {} -u {} -c {}";

    static constexpr const char* TPM2_EVICT_CONTROL_CMD =
        "tpm2_evictcontrol -C o -c {} {}";

    static constexpr const char* TPM2_EVICT_REMOVE_CMD =
        "tpm2_evictcontrol -C o -c {}";

    static constexpr const char* TPM2_READ_PUBLIC_CMD =
        "tpm2_readpublic -c {} -f pem -o {}";

    /**
     * @brief Execute a TPM command with formatted arguments
     * @param cmdTemplate Command template string
     * @param args Arguments to format into the template
     * @return error_code indicating success or failure
     */
    template <typename... Args>
    boost::system::error_code executeTPMCommand(const char* cmdTemplate,
                                                Args&&... args)
    {
        std::string cmd = std::vformat(
            cmdTemplate, std::make_format_args(std::forward<Args>(args)...));
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        int result = system(cmd.c_str());

        if (result != 0)
        {
            LOG_ERROR("TPM command failed: {}", cmd);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        return boost::system::error_code{};
    }

    // OpenSSL with TPM2 Provider Command Templates (with empty password
    // passthrough)
    static constexpr const char* OPENSSL_REQ_NEW_CMD =
        R"(openssl req -new -provider tpm2 -provider default -key "handle:{}" -passin pass: -out {} -subj "{}" 2>&1)";

    // {notBefore} and {notAfter} are filled at call time via certNotBefore()
    // and certNotAfter().  notBefore is the Unix epoch so that clock drift /
    // NTP jumps never cause X509_V_ERR_CERT_NOT_YET_VALID.  notAfter is 50
    // years from the moment the certificate is created.
    static constexpr const char* OPENSSL_X509_SELFSIGN_CMD =
        R"(openssl x509 -req -in {} -signkey "handle:{}" -provider tpm2 -provider default -passin pass: -out {} -set_serial {} -not_before {} -not_after {} 2>&1)";

    static constexpr const char* OPENSSL_X509_SELFSIGN_EXT_CMD =
        R"(openssl x509 -req -in {} -signkey "handle:{}" -provider tpm2 -provider default -passin pass: -out {} -set_serial {} -not_before {} -not_after {} -extfile {} -extensions {} 2>&1)";

    static constexpr const char* OPENSSL_X509_CA_SIGN_CMD =
        R"(openssl x509 -req -in {} -CA {} -CAkey "handle:{}" -provider tpm2 -provider default -passin pass: -set_serial {} -out {} -not_before {} -not_after {} 2>&1)";

    static constexpr const char* OPENSSL_X509_CA_SIGN_EXT_CMD =
        R"(openssl x509 -req -in {} -CA {} -CAkey "handle:{}" -provider tpm2 -provider default -passin pass: -set_serial {} -out {} -not_before {} -not_after {} -extfile {} -extensions {} 2>&1)";

    // Returns the fixed notBefore date: Unix epoch in ASN1 GeneralizedTime.
    static std::string certNotBefore()
    {
        return "19700101000000Z";
    }

    // Returns notAfter = now + 50 years in ASN1 GeneralizedTime
    // (YYYYMMDDHHMMSSZ).
    static std::string certNotAfter()
    {
        using namespace std::chrono;
        auto now = system_clock::now();
        // Add 50 years as days (365.2425 average days/year).
        auto future = now + duration_cast<system_clock::duration>(years{50});
        std::time_t t = system_clock::to_time_t(future);
        std::tm tm{};
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        gmtime_r(&t, &tm);
        return std::format("{:04}{:02}{:02}{:02}{:02}{:02}Z", tm.tm_year + 1900,
                           tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
                           tm.tm_sec);
    }

    Tpm2CertManager()
    {
        initialize();
    }

    /**
     * @brief Initialize TPM2 provider
     */
    void initialize()
    {
        // Load default provider first into global context (required for SSL/TLS
        // operations)
        defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
        if (!defaultProvider)
        {
            LOG_ERROR("Failed to load default provider");
            return;
        }
        LOG_INFO("Default provider loaded successfully");

        // Configure TPM2 provider to use resource manager for concurrent access
        // The TPM Resource Manager (/dev/tpmrm0) handles serialization
        // automatically
        const char* tcti_conf = "device:/dev/tpmrm0";
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (setenv("TPM2OPENSSL_TCTI", tcti_conf, 1) != 0)
        {
            LOG_WARNING("Failed to set TPM2OPENSSL_TCTI environment variable");
            // Continue anyway - provider may have default configuration
        }

        // Load TPM2 provider into global context so SSL_CTX instances can
        // access it
        tpmProvider = OSSL_PROVIDER_load(nullptr, "tpm2");

        if (tpmProvider)
        {
            auto result = OSSL_PROVIDER_self_test(tpmProvider);
            if (result != 1)
            {
                LOG_ERROR("TPM2 provider self test failed");
                OSSL_PROVIDER_unload(tpmProvider);
                tpmProvider = nullptr;
                return;
            }
            initialized = true;
            LOG_INFO("TPM2 provider initialized successfully");
            return;
        }

        LOG_ERROR("Failed to load TPM2 provider");
    }

  public:
    Tpm2CertManager(const Tpm2CertManager&) = delete;
    Tpm2CertManager& operator=(const Tpm2CertManager&) = delete;
    Tpm2CertManager(Tpm2CertManager&&) = delete;
    Tpm2CertManager& operator=(Tpm2CertManager&&) = delete;
    ~Tpm2CertManager()
    {
        if (tpmProvider)
        {
            OSSL_PROVIDER_unload(tpmProvider);
        }
        if (defaultProvider)
        {
            OSSL_PROVIDER_unload(defaultProvider);
        }
        if (tpmProviderHandle)
        {
            dlclose(tpmProviderHandle);
            tpmProviderHandle = nullptr;
        }
        if (libCtx)
        {
            OSSL_LIB_CTX_free(libCtx);
            libCtx = nullptr;
        }
    }

    static bool isEccSupported()
    {
        static int supported = -1;
        if (supported == -1)
        {
            int ret = system( // NOLINT(concurrency-mt-unsafe)
                "tpm2_getcap algorithms 2>/dev/null | grep -q '^ecc:'");
            supported = (ret == 0) ? 1 : 0;
            LOG_INFO("TPM ECC algorithm support: {}",
                     (supported == 1) ? "yes" : "no");
        }
        return supported == 1;
    }

    /**
     * @brief Get singleton instance
     */
    static Tpm2CertManager& getInstance()
    {
        static Tpm2CertManager instance;
        return instance;
    }

    /**
     * @brief Get the library context used by TPM provider
     */
    OSSL_LIB_CTX* getLibCtx() const
    {
        return libCtx;
    }

    /**
     * @brief Check if TPM2 provider is initialized
     */
    bool isInitialized() const
    {
        return initialized;
    }

    /**
     * @brief Load private key from TPM2
     * @param tpmUri TPM2 URI (e.g., "handle:0x81000001" or
     * "object:path/to/key")
     * @param outKey Output parameter for the loaded key
     * @return error_code indicating success or failure
     */
    boost::system::error_code loadPrivateKeyFromTpm(const std::string& tpmUri,
                                                    EVP_PKEYPtr& outKey)
    {
        if (!initialized)
        {
            LOG_ERROR("TPM2 provider not initialized");
            return boost::system::errc::make_error_code(
                boost::system::errc::not_supported);
        }

        OSSL_STORE_CTX* storeCtx = nullptr;
        OSSL_STORE_INFO* info = nullptr;
        const char* propq = "?provider=tpm2";
        EVP_PKEY* pkey = nullptr;

        storeCtx = OSSL_STORE_open_ex(tpmUri.c_str(), libCtx, propq, nullptr,
                                      nullptr, nullptr, nullptr, nullptr);

        if (!storeCtx)
        {
            LOG_ERROR("Failed to open store context for URI: {}", tpmUri);
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        while (!OSSL_STORE_eof(storeCtx) && pkey == nullptr)
        {
            info = OSSL_STORE_load(storeCtx);

            if (info == nullptr)
            {
                if (OSSL_STORE_error(storeCtx))
                {
                    LOG_ERROR("Error during OSSL_STORE_load (PrivateKey)");
                }
                continue;
            }

            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
            {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
                LOG_INFO("Private key loaded from TPM URI: {}", tpmUri);
            }

            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(storeCtx);

        if (pkey == nullptr)
        {
            LOG_ERROR("No private key found at URI: {}", tpmUri);
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        outKey = makeEVPPKeyPtr(pkey);
        return boost::system::error_code{};
    }

    /**
     * @brief Load certificate from TPM2
     * @param tpmUri TPM2 URI for certificate
     * @param outCert Output parameter for the loaded certificate
     * @return error_code indicating success or failure
     */
    boost::system::error_code loadCertificateFromTpm(const std::string& tpmUri,
                                                     X509Ptr& outCert)
    {
        if (!initialized)
        {
            LOG_ERROR("TPM2 provider not initialized");
            return boost::system::errc::make_error_code(
                boost::system::errc::not_supported);
        }

        OSSL_STORE_CTX* storeCtx = nullptr;
        OSSL_STORE_INFO* info = nullptr;
        const char* propq = "?provider=tpm2";
        X509* cert = nullptr;

        storeCtx = OSSL_STORE_open_ex(tpmUri.c_str(), libCtx, propq, nullptr,
                                      nullptr, nullptr, nullptr, nullptr);

        if (!storeCtx)
        {
            LOG_ERROR("Failed to open store context for URI: {}", tpmUri);
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        while (!OSSL_STORE_eof(storeCtx) && cert == nullptr)
        {
            info = OSSL_STORE_load(storeCtx);

            if (info == nullptr)
            {
                if (OSSL_STORE_error(storeCtx))
                {
                    LOG_ERROR("Error during OSSL_STORE_load (Certificate)");
                }
                continue;
            }

            if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT)
            {
                cert = OSSL_STORE_INFO_get1_CERT(info);
                LOG_INFO("Certificate loaded from TPM URI: {}", tpmUri);
            }

            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(storeCtx);

        if (cert == nullptr)
        {
            LOG_ERROR("No certificate found at URI: {}", tpmUri);
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        outCert = makeX509Ptr(cert);
        return boost::system::error_code{};
    }

    /**
     * @brief Load CA certificate from TPM2
     * @param tpmUri TPM2 URI for CA certificate
     * @param outCaCert Output parameter for the loaded CA certificate
     * @return error_code indicating success or failure
     */
    boost::system::error_code loadCACertificateFromTpm(
        const std::string& tpmUri, X509Ptr& outCaCert)
    {
        X509Ptr cert = makeX509Ptr(nullptr);
        auto ec = loadCertificateFromTpm(tpmUri, cert);
        if (ec)
        {
            return ec;
        }

        // Verify this is a CA certificate
        if (!X509_check_ca(cert.get()))
        {
            LOG_ERROR("Certificate at URI {} is not a CA certificate", tpmUri);
            return boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
        }

        outCaCert = std::move(cert);
        LOG_INFO("CA certificate loaded from TPM URI: {}", tpmUri);
        return boost::system::error_code{};
    }

    /**
     * @brief Export certificate from TPM to PEM file
     * @param tpmUri TPM2 URI of the certificate
     * @param pemFilePath Output PEM file path
     * @return error_code indicating success or failure
     */
    boost::system::error_code exportCertificateToPemFile(
        const std::string& tpmUri, const std::string& pemFilePath)
    {
        X509Ptr cert = makeX509Ptr(nullptr);
        auto ec = loadCertificateFromTpm(tpmUri, cert);
        if (ec)
        {
            return ec;
        }

        FilePtr fp = makeFilePtr(fopen(pemFilePath.c_str(), "w"));
        if (!fp)
        {
            LOG_ERROR("Failed to open file for writing: {}", pemFilePath);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        int result = PEM_write_X509(fp.get(), cert.get());
        if (result != 1)
        {
            LOG_ERROR("Failed to write certificate to PEM file: {}",
                      pemFilePath);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        LOG_INFO("Certificate exported to PEM file: {}", pemFilePath);
        return boost::system::error_code{};
    }

    /**
     * @brief Export private key from TPM to PEM file (if TPM policy allows)
     * @param tpmUri TPM2 URI of the private key
     * @param pemFilePath Output PEM file path
     * @param password Optional password for encryption
     * @return error_code indicating success or failure
     */
    boost::system::error_code exportPrivateKeyToPemFile(
        const std::string& tpmUri, const std::string& pemFilePath,
        const std::string& password = "")
    {
        EVP_PKEYPtr key = makeEVPPKeyPtr(nullptr);
        auto ec = loadPrivateKeyFromTpm(tpmUri, key);
        if (ec)
        {
            return ec;
        }

        FilePtr fp = makeFilePtr(fopen(pemFilePath.c_str(), "w"));
        if (!fp)
        {
            LOG_ERROR("Failed to open file for writing: {}", pemFilePath);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        int result = 0;
        if (password.empty())
        {
            result = PEM_write_PKCS8PrivateKey(fp.get(), key.get(), nullptr,
                                               nullptr, 0, nullptr, nullptr);
        }
        else
        {
            result = PEM_write_PKCS8PrivateKey(
                fp.get(), key.get(), EVP_aes_256_gcm(), password.c_str(),
                static_cast<int>(password.length()), nullptr, nullptr);
        }

        if (result != 1)
        {
            LOG_ERROR("Failed to write private key to PEM file: {}",
                      pemFilePath);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        LOG_INFO("Private key exported to PEM file: {}", pemFilePath);
        return boost::system::error_code{};
    }

    /**
     * @brief Verify certificate chain using TPM-stored CA
     * @param cert Certificate to verify
     * @param caTpmUri TPM2 URI of the CA certificate
     * @return error_code indicating success or failure
     */
    boost::system::error_code verifyCertificateWithTpmCA(
        const X509Ptr& cert, const std::string& caTpmUri)
    {
        if (!cert)
        {
            LOG_ERROR("Invalid certificate pointer");
            return boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
        }

        X509Ptr caCert = makeX509Ptr(nullptr);
        auto ec = loadCACertificateFromTpm(caTpmUri, caCert);
        if (ec)
        {
            return ec;
        }

        EVP_PKEY* caKey = X509_get_pubkey(caCert.get());
        if (!caKey)
        {
            LOG_ERROR("Failed to extract public key from CA certificate");
            return boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
        }

        int result = X509_verify(cert.get(), caKey);
        EVP_PKEY_free(caKey);

        if (result != 1)
        {
            LOG_ERROR("Certificate verification failed");
            return boost::system::errc::make_error_code(
                boost::system::errc::permission_denied);
        }

        LOG_INFO("Certificate verified successfully with TPM CA");
        return boost::system::error_code{};
    }

    /**
     * @brief Get certificate information from TPM
     * @param tpmUri TPM2 URI of the certificate
     * @param outInfo Output parameter for certificate information
     * @return error_code indicating success or failure
     */
    boost::system::error_code getCertificateInfo(const std::string& tpmUri,
                                                 std::string& outInfo)
    {
        X509Ptr cert = makeX509Ptr(nullptr);
        auto ec = loadCertificateFromTpm(tpmUri, cert);
        if (ec)
        {
            return ec;
        }

        BIOPtr bio = makeBIOPtr(BIO_new(BIO_s_mem()));
        if (!bio)
        {
            LOG_ERROR("Failed to create BIO");
            return boost::system::errc::make_error_code(
                boost::system::errc::not_enough_memory);
        }

        X509_print(bio.get(), cert.get());

        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio.get(), &mem);

        if (!mem || !mem->data)
        {
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        outInfo = std::string(mem->data, mem->length);
        return boost::system::error_code{};
    }

    /**
     * @brief Create TPM primary key in owner hierarchy
     * @param outContext Output file path for primary key context
     * @return error_code indicating success or failure
     */
    boost::system::error_code createTPMPrimaryKey(
        const std::string& outContext, const std::string& hashAlgo = "sha256",
        const std::string& signAlgo = "rsa2048")
    {
        auto result =
            executeTPMCommand("tpm2_createprimary -C o -g {} -G {} -c {}",
                              hashAlgo, signAlgo, outContext);

        if (result)
        {
            LOG_ERROR("Failed to create TPM primary key with hash={}, sign={}",
                      hashAlgo, signAlgo);
            return result;
        }

        LOG_INFO("TPM primary key created: {} (hash={}, sign={})", outContext,
                 hashAlgo, signAlgo);
        return boost::system::error_code{};
    }

    /**
     * @brief Create TPM key as child of primary
     * @param primaryContext Primary key context file
     * @param outPrivate Output file for private key blob
     * @param outPublic Output file for public key blob
     * @return error_code indicating success or failure
     */
    boost::system::error_code createTPMKey(const std::string& primaryContext,
                                           const std::string& outPrivate,
                                           const std::string& outPublic)
    {
        const char* cmdTemplate = isEccSupported() ? TPM2_CREATE_KEY_ECC_CMD
                                                   : TPM2_CREATE_KEY_RSA_CMD;
        auto ec = executeTPMCommand(cmdTemplate, primaryContext, outPrivate,
                                    outPublic);
        if (ec && isEccSupported())
        {
            LOG_WARNING("ECC key creation failed, falling back to RSA2048");
            ec = executeTPMCommand(TPM2_CREATE_KEY_RSA_CMD, primaryContext,
                                   outPrivate, outPublic);
        }

        if (ec)
        {
            LOG_ERROR("Failed to create TPM key");
            return ec;
        }

        LOG_INFO("TPM key created: {} / {}", outPrivate, outPublic);
        return boost::system::error_code{};
    }

    /**
     * @brief Load TPM key and make it persistent
     * @param primaryContext Primary key context file
     * @param privateBlob Private key blob file
     * @param publicBlob Public key blob file
     * @param persistentHandle Persistent handle (e.g., "0x81000001")
     * @return error_code indicating success or failure
     */
    boost::system::error_code loadAndPersistTPMKey(
        const std::string& primaryContext, const std::string& privateBlob,
        const std::string& publicBlob, const std::string& persistentHandle)
    {
        // Step 1: Remove any existing key at this handle (ignore errors if none
        // exists)
        LOG_DEBUG("Removing any existing key at handle {}", persistentHandle);
        std::ignore =
            executeTPMCommand(TPM2_EVICT_REMOVE_CMD, persistentHandle);
        // Ignore error - it's OK if no key exists at this handle

        // Step 2: Load key
        TempDir td;
        std::string tempCtx = td.path("temp_key.ctx");
        auto ec = executeTPMCommand(TPM2_LOAD_KEY_CMD, primaryContext,
                                    privateBlob, publicBlob, tempCtx);
        if (ec)
        {
            LOG_ERROR("Failed to load TPM key");
            return ec;
        }

        // Step 3: Make persistent
        ec = executeTPMCommand(TPM2_EVICT_CONTROL_CMD, tempCtx,
                               persistentHandle);
        if (ec)
        {
            LOG_ERROR("Failed to persist TPM key at {}", persistentHandle);
            return ec;
        }

        LOG_INFO("TPM key persisted at {}", persistentHandle);
        return boost::system::error_code{};
    }

    /**
     * @brief Generate CSR using TPM key via TPM2 provider
     * @param tpmKeyHandle TPM persistent handle (e.g., "0x81000001")
     * @param subject Certificate subject (e.g., "/C=US/CN=Test")
     * @param outCSR Output CSR file path
     * @return error_code indicating success or failure
     */
    boost::system::error_code generateCSRWithTPMKey(
        const std::string& tpmKeyHandle, const std::string& subject,
        const std::string& outCSR)
    {
        auto ec = executeTPMCommand(OPENSSL_REQ_NEW_CMD, tpmKeyHandle, outCSR,
                                    subject);
        if (ec)
        {
            LOG_ERROR("Failed to generate CSR with TPM key {}", tpmKeyHandle);
            return ec;
        }

        LOG_INFO("CSR generated with TPM key: {}", outCSR);
        return boost::system::error_code{};
    }

    /**
     * @brief Self-sign certificate using TPM key
     * @param csrFile CSR file path
     * @param tpmKeyHandle TPM persistent handle for signing
     * @param outCert Output certificate file path
     * @param days Validity period in days
     * @param extensions Certificate extensions (e.g., "v3_ca")
     * @return error_code indicating success or failure
     */
    boost::system::error_code selfSignCertificateWithTPM(
        const std::string& csrFile, const std::string& tpmKeyHandle,
        const std::string& outCert, [[maybe_unused]] int days,
        const std::string& extensions = "")
    {
        // Generate a cryptographically secure random serial number
        uint64_t serial = 0;
        std::array<unsigned char, sizeof(serial)> serialBytes{};
        RAND_bytes(serialBytes.data(), static_cast<int>(serialBytes.size()));
        std::memcpy(&serial, serialBytes.data(), sizeof(serial));

        if (!extensions.empty())
        {
            // Create a temporary config file for extensions
            TempDir td;
            std::string extFile = td.path("cert_ext.cnf");
            std::ofstream ofs(extFile);
            if (extensions == "v3_ca")
            {
                ofs << "[v3_ca]\n";
                ofs << "basicConstraints = critical,CA:TRUE\n";
                ofs << "keyUsage = critical,digitalSignature,keyCertSign,cRLSign\n";
                ofs << "subjectKeyIdentifier = hash\n";
                ofs << "authorityKeyIdentifier = keyid:always,issuer\n";
            }
            else
            {
                ofs << "[v3_req]\n";
                ofs << "basicConstraints = CA:FALSE\n";
                ofs << "keyUsage = digitalSignature,keyEncipherment\n";
            }
            ofs.close();

            auto notBefore = certNotBefore();
            auto notAfter = certNotAfter();
            auto ec = executeTPMCommand(
                OPENSSL_X509_SELFSIGN_EXT_CMD, csrFile, tpmKeyHandle, outCert,
                serial, notBefore, notAfter, extFile, extensions);
            if (ec)
            {
                LOG_ERROR("Failed to self-sign certificate with TPM key");
                return ec;
            }
        }
        else
        {
            auto notBefore = certNotBefore();
            auto notAfter = certNotAfter();
            auto ec = executeTPMCommand(OPENSSL_X509_SELFSIGN_CMD, csrFile,
                                        tpmKeyHandle, outCert, serial,
                                        notBefore, notAfter);
            if (ec)
            {
                LOG_ERROR("Failed to self-sign certificate with TPM key");
                return ec;
            }
        }

        LOG_INFO("Certificate self-signed with TPM key: {}", outCert);
        return boost::system::error_code{};
    }

    /**
     * @brief Write an OpenSSL extensions file for a server or client entity
     * certificate.
     * @param extFile Output extensions file path
     * @param extensions Section name: "v3_server" or "v3_client"
     */
    /**
     * @brief RAII owner of a private 0700 temporary directory.
     *
     * Creates a unique directory under the system temp path via mkdtemp.
     * Because the directory is mode 0700 and owned by the daemon's UID, no
     * other local user or process can observe, open, or race-replace files
     * placed inside it.  The entire directory tree is removed on destruction.
     *
     * Usage:
     *   TempDir td;
     *   std::string keyFile = td.path("key.priv");   // e.g.
     * /tmp/tpm-XXXXXX/key.priv
     */
    class TempDir
    {
      public:
        TempDir()
        {
            // mkdtemp(3) requires a writable char[] template — it replaces the
            // trailing XXXXXX in-place and atomically mkdir's the result with
            // mode 0700.  No other user can observe or access files created
            // inside the returned directory.
            std::string tmpl = "/tmp/tpm-XXXXXX";
            if (mkdtemp(tmpl.data()) == nullptr)
            {
                throw std::runtime_error(
                    "TempDir: mkdtemp failed to create private temp directory");
            }
            dir_ = tmpl;
        }

        ~TempDir()
        {
            if (!dir_.empty())
            {
                std::filesystem::remove_all(dir_);
            }
        }

        // Non-copyable, non-movable — owns the directory lifetime.
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        TempDir(TempDir&&) = delete;
        TempDir& operator=(TempDir&&) = delete;

        /** Return the full path to a named file inside this private directory.
         */
        std::string path(const std::string& filename) const
        {
            return (std::filesystem::path(dir_) / filename).string();
        }

        /** Return the directory path itself. */
        const std::string& dir() const
        {
            return dir_;
        }

      private:
        std::string dir_;
    };

    static void writeEntityExtFile(const std::string& extFile,
                                   const std::string& extensions)
    {
        std::ofstream ofs(extFile);
        if (extensions == "v3_server")
        {
            ofs << "[v3_server]\n";
            ofs << "basicConstraints = CA:FALSE\n";
            if (isEccSupported())
            {
                ofs << "keyUsage = critical,digitalSignature\n";
            }
            else
            {
                ofs << "keyUsage = critical,digitalSignature,keyEncipherment\n";
            }
            ofs << "extendedKeyUsage = serverAuth\n";
            ofs << "subjectKeyIdentifier = hash\n";
            ofs << "authorityKeyIdentifier = keyid,issuer\n";
        }
        else if (extensions == "v3_client")
        {
            ofs << "[v3_client]\n";
            ofs << "basicConstraints = CA:FALSE\n";
            if (isEccSupported())
            {
                ofs << "keyUsage = critical,digitalSignature\n";
            }
            else
            {
                ofs << "keyUsage = critical,digitalSignature,keyEncipherment\n";
            }
            ofs << "extendedKeyUsage = clientAuth\n";
            ofs << "subjectKeyIdentifier = hash\n";
            ofs << "authorityKeyIdentifier = keyid,issuer\n";
        }
    }

    /**
     * @brief Sign certificate with CA using TPM CA key
     * @param csrFile CSR file path
     * @param caCertFile CA certificate file
     * @param caKeyHandle TPM persistent handle of CA key
     * @param outCert Output certificate file path
     * @param days Validity period in days
     * @param extensions Certificate extensions
     * @return error_code indicating success or failure
     */
    boost::system::error_code signCertificateWithTPMCA(
        const std::string& csrFile, const std::string& caCertFile,
        const std::string& caKeyHandle, const std::string& outCert,
        [[maybe_unused]] int days, const std::string& extensions = "")
    {
        // Generate a cryptographically secure random serial number
        uint64_t serial = 0;
        std::array<unsigned char, sizeof(serial)> serialBytes{};
        RAND_bytes(serialBytes.data(), static_cast<int>(serialBytes.size()));
        std::memcpy(&serial, serialBytes.data(), sizeof(serial));

        if (!extensions.empty())
        {
            // Create a temporary config file for extensions
            TempDir td;
            std::string extFile = td.path("cert_ext_ca_sign.cnf");
            writeEntityExtFile(extFile, extensions);

            auto notBefore = certNotBefore();
            auto notAfter = certNotAfter();
            auto ec = executeTPMCommand(
                OPENSSL_X509_CA_SIGN_EXT_CMD, csrFile, caCertFile, caKeyHandle,
                serial, outCert, notBefore, notAfter, extFile, extensions);
            if (ec)
            {
                LOG_ERROR("Failed to sign certificate with TPM CA key");
                return ec;
            }
        }
        else
        {
            auto notBefore = certNotBefore();
            auto notAfter = certNotAfter();
            auto ec = executeTPMCommand(OPENSSL_X509_CA_SIGN_CMD, csrFile,
                                        caCertFile, caKeyHandle, serial,
                                        outCert, notBefore, notAfter);
            if (ec)
            {
                LOG_ERROR("Failed to sign certificate with TPM CA key");
                return ec;
            }
        }

        LOG_INFO("Certificate signed with TPM CA key: {}", outCert);
        return boost::system::error_code{};
    }

    /**
     * @brief Store certificate in TPM NV index
     * @param certFile Certificate file path
     * @param nvIndex NV index (e.g., "0x1500002")
     * @return error_code indicating success or failure
     */
    boost::system::error_code storeCertificateInTPMNV(
        const std::string& certFile, const std::string& nvIndex)
    {
        // TPM NV storage size limit (typically 2048 bytes for most TPMs)
        constexpr size_t MAX_TPM_NV_SIZE = 2048;

        std::filesystem::path certPath(certFile);
        if (!std::filesystem::exists(certPath))
        {
            LOG_ERROR("Certificate file not found: {}", certFile);
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        // Read the certificate file to extract only the leaf certificate
        TempDir td;
        std::string tempLeafCertFile = td.path("tpm_leaf_cert.pem");

        auto extractResult =
            executeTPMCommand("openssl x509 -in {} -out {} 2>/dev/null",
                              certFile, tempLeafCertFile);
        if (extractResult)
        {
            LOG_ERROR("Failed to extract leaf certificate from {}", certFile);
            return extractResult;
        }

        // Get the size of the leaf certificate only
        size_t certSize = std::filesystem::file_size(tempLeafCertFile);

        // Check if certificate size exceeds TPM NV limit
        if (certSize > MAX_TPM_NV_SIZE)
        {
            LOG_ERROR(
                "Certificate size ({} bytes) exceeds TPM NV limit ({} bytes) for index {}",
                certSize, MAX_TPM_NV_SIZE, nvIndex);
            return boost::system::errc::make_error_code(
                boost::system::errc::file_too_large);
        }

        // Check if NV index already exists
        auto checkResult =
            executeTPMCommand("tpm2_nvreadpublic {} 2>/dev/null", nvIndex);
        bool nvExists = !checkResult;

        if (nvExists)
        {
            LOG_DEBUG("NV index {} already exists, deleting it", nvIndex);
            // Delete existing NV index
            auto deleteResult =
                executeTPMCommand("tpm2_nvundefine {} 2>&1", nvIndex);
            if (deleteResult)
            {
                LOG_ERROR("Failed to delete existing TPM NV index {}", nvIndex);
                return deleteResult;
            }
        }

        // Define NV index with the correct size
        auto defineResult = executeTPMCommand(
            R"(tpm2_nvdefine {} -C o -s {} -a "ownerread|ownerwrite" 2>&1)",
            nvIndex, certSize);

        if (defineResult)
        {
            LOG_ERROR("Failed to define TPM NV index {} with size {}", nvIndex,
                      certSize);
            return defineResult;
        }

        // Write leaf certificate to NV
        auto writeResult = executeTPMCommand("tpm2_nvwrite {} -C o -i {} 2>&1",
                                             nvIndex, tempLeafCertFile);

        if (writeResult)
        {
            LOG_ERROR("Failed to write certificate to TPM NV {}", nvIndex);
            return writeResult;
        }

        LOG_INFO("Leaf certificate ({} bytes) stored in TPM NV index {}",
                 certSize, nvIndex);
        return boost::system::error_code{};
    }

    /**
     * @brief Read certificate from TPM NV index
     * @param nvIndex NV index (e.g., "0x1500002")
     * @param outCert Output certificate pointer
     * @return error_code indicating success or failure
     */
    static boost::system::error_code readCertificateFromTPMNV(
        const std::string& nvIndex, X509Ptr& outCert)
    {
        TempDir td;
        std::string tempFile = td.path("cert.pem");
        // Redirect only stdout to the temp file; send stderr to /dev/null so
        // that tpm2-tools warning/info lines are not mixed into the PEM data.
        std::string cmd = std::format("tpm2_nvread -C o {} > {} 2>/dev/null",
                                      nvIndex, tempFile);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(cmd.c_str()) != 0)
        {
            LOG_ERROR("Failed to read from TPM NV index {}", nvIndex);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        // Load certificate from temp file
        FilePtr fp = makeFilePtr(fopen(tempFile.c_str(), "r"));
        if (!fp)
        {
            LOG_ERROR("Failed to open temp certificate file");
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        X509* cert = PEM_read_X509(fp.get(), nullptr, nullptr, nullptr);
        fp.reset(); // Close file before parsing

        if (!cert)
        {
            LOG_ERROR("Failed to parse certificate from NV index {}", nvIndex);
            return boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
        }

        outCert = makeX509Ptr(cert);
        LOG_INFO("Certificate read from TPM NV index {}", nvIndex);
        return boost::system::error_code{};
    }

    /**
     * @brief Delete TPM NV index
     * @param nvIndex NV index to delete
     * @return error_code indicating success or failure
     */
    static boost::system::error_code deleteTPMNVIndex(
        const std::string& nvIndex)
    {
        std::string cmd = std::format("tpm2_nvundefine -C o {} 2>&1", nvIndex);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(cmd.c_str()) != 0)
        {
            LOG_ERROR("Failed to delete TPM NV index {}", nvIndex);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        LOG_INFO("TPM NV index deleted: {}", nvIndex);
        return boost::system::error_code{};
    }

    /**
     * @brief Delete TPM persistent handle
     * @param handle Persistent handle to delete
     * @return error_code indicating success or failure
     */
    static boost::system::error_code deleteTPMPersistentHandle(
        const std::string& handle)
    {
        std::string cmd =
            std::format("tpm2_evictcontrol -C o -c {} 2>&1", handle);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(cmd.c_str()) != 0)
        {
            LOG_ERROR("Failed to delete TPM persistent handle {}", handle);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        LOG_INFO("TPM persistent handle deleted: {}", handle);
        return boost::system::error_code{};
    }

    /**
     * @brief Import existing PEM private key into TPM as persistent object
     * @param keyFile Path to PEM private key file
     * @param persistentHandle Persistent handle for the key (e.g.,
     * "0x81000001")
     * @return error_code indicating success or failure
     */
    // Inspect a PEM key file and return the tpm2_import -G algorithm string.
    // The CA is generated with `openssl genpkey -algorithm EC
    // -pkeyopt ec_paramgen_curve:P-384` which produces PKCS#8 PEM
    // ("-----BEGIN PRIVATE KEY-----").  We ask OpenSSL to print the curve
    // name and map it to the tpm2_import token.
    static std::string detectTpmAlgo(const std::string& keyFile)
    {
        // Ask openssl for the curve name; output is like "ASN1 OID: secp384r1"
        std::string cmd = std::format(
            "openssl pkey -in {} -noout -text 2>&1 | grep -i 'ASN1 OID'",
            keyFile);
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe)
        {
            return "ecc384"; // safe default for the shipped P-384 CA key
        }
        std::array<char, 256> buf{};
        std::string out;
        while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr)
        {
            out += buf.data();
        }
        pclose(pipe);

        if (out.find("384") != std::string::npos)
        {
            return "ecc384";
        }
        if (out.find("256") != std::string::npos)
        {
            return "ecc256";
        }
        if (out.find("521") != std::string::npos)
        {
            return "ecc521";
        }
        // Fall back: check for RSA
        std::string rsaCmd = std::format(
            "openssl pkey -in {} -noout -text 2>&1 | grep -i 'rsa'", keyFile);
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        FILE* rsaPipe = popen(rsaCmd.c_str(), "r");
        if (rsaPipe)
        {
            std::array<char, 256> rbuf{};
            std::string rout;
            while (fgets(rbuf.data(), static_cast<int>(rbuf.size()), rsaPipe) !=
                   nullptr)
            {
                rout += rbuf.data();
            }
            pclose(rsaPipe);
            if (!rout.empty())
            {
                return "rsa2048";
            }
        }
        return "ecc384"; // shipped CA default
    }

    boost::system::error_code importPrivateKeyToTPM(
        const std::string& keyFile, const std::string& persistentHandle)
    {
        // Check if key file exists
        if (!std::filesystem::exists(keyFile))
        {
            LOG_ERROR("Private key file not found: {}", keyFile);
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        // Create primary key context inside a private temp dir
        TempDir td;
        std::string primaryCtx = td.path("primary_import.ctx");
        auto ec = createTPMPrimaryKey(primaryCtx);
        if (ec)
        {
            LOG_ERROR("Failed to create TPM primary key for import");
            return ec;
        }

        // The CA is a PKCS#8 EC key (openssl genpkey -algorithm EC
        // -pkeyopt ec_paramgen_curve:P-384).  tpm2_import requires a bare
        // SEC1 DER key.  Convert via:
        //   openssl pkcs8 -nocrypt (→ PEM SEC1) | openssl ec -outform DER
        // Use a pipe so no intermediate SEC1 PEM touches disk.
        const std::string tpmAlgo = detectTpmAlgo(keyFile);
        LOG_INFO("Importing key {} as TPM algo {}", keyFile, tpmAlgo);

        std::string derKeyFile = td.path("imported_key.der");
        ec = executeTPMCommand("openssl pkcs8 -nocrypt -in {} 2>/dev/null"
                               " | openssl ec -outform DER -out {} 2>&1",
                               keyFile, derKeyFile);
        if (ec)
        {
            LOG_ERROR("Failed to convert PKCS#8 key {} to SEC1 DER", keyFile);
            return ec;
        }

        // Import the SEC1 DER key into TPM.
        std::string pubFile = td.path("imported_key.pub");
        std::string privFile = td.path("imported_key.priv");
        std::string importCmd =
            std::format("tpm2_import -C {} -G {} -i {} -u {} -r {} 2>&1",
                        primaryCtx, tpmAlgo, derKeyFile, pubFile, privFile);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(importCmd.c_str()) != 0)
        {
            LOG_ERROR("Failed to import private key {} into TPM", keyFile);
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        // Load and persist the imported key (td cleans up all temp files)
        ec = loadAndPersistTPMKey(primaryCtx, privFile, pubFile,
                                  persistentHandle);
        if (ec)
        {
            LOG_ERROR("Failed to persist imported key at handle {}",
                      persistentHandle);
            return ec;
        }

        LOG_INFO("Private key imported to TPM persistent handle: {}",
                 persistentHandle);
        return boost::system::error_code{};
    }

    /**
     * @brief Create complete CA certificate with TPM key
     * @param persistentHandle TPM handle for CA key (e.g., "0x81000001")
     * @param nvIndex NV index for CA cert (e.g., "0x1500002")
     * @param subject CA subject
     * @param days Validity period
     * @param primaryContext Primary key context file
     * @return error_code indicating success or failure
     */
    boost::system::error_code createCACertificateInTPM(
        const std::string& persistentHandle, const std::string& nvIndex,
        const std::string& subject, int days,
        const std::string& primaryContext = "")
    {
        TempDir td;
        // Create primary key if needed
        std::string primaryCtx =
            primaryContext.empty() ? td.path("primary.ctx") : primaryContext;
        if (!std::filesystem::exists(primaryCtx))
        {
            auto ec = createTPMPrimaryKey(primaryCtx);
            if (ec)
                return ec;
        }

        // Create CA key
        std::string privBlob = td.path("ca_key.priv");
        std::string pubBlob = td.path("ca_key.pub");
        auto ec = createTPMKey(primaryCtx, privBlob, pubBlob);
        if (ec)
            return ec;

        // Load and persist
        ec = loadAndPersistTPMKey(primaryCtx, privBlob, pubBlob,
                                  persistentHandle);
        if (ec)
            return ec;

        // Generate CSR
        std::string csrFile = td.path("ca.csr");
        ec = generateCSRWithTPMKey(persistentHandle, subject, csrFile);
        if (ec)
            return ec;

        // Self-sign
        std::string certFile = td.path("ca_cert.pem");
        ec = selfSignCertificateWithTPM(csrFile, persistentHandle, certFile,
                                        days, "v3_ca");
        if (ec)
            return ec;

        // Store in NV (td cleans up all temp files on scope exit)
        ec = storeCertificateInTPMNV(certFile, nvIndex);
        if (ec)
            return ec;

        LOG_INFO("CA certificate created in TPM: {} / {}", persistentHandle,
                 nvIndex);
        return boost::system::error_code{};
    }

    /**
     * @brief Create entity certificate signed by TPM CA
     * @param persistentHandle TPM handle for entity key
     * @param nvIndex NV index for entity cert
     * @param subject Entity subject
     * @param caHandle TPM handle of CA key
     * @param caNVIndex NV index of CA cert
     * @param days Validity period
     * @param extensions Certificate extensions
     * @param primaryContext Primary key context file
     * @return error_code indicating success or failure
     */
    boost::system::error_code createEntityCertificateInTPM(
        const std::string& persistentHandle, const std::string& nvIndex,
        const std::string& subject, const std::string& caHandle,
        const std::string& caNVIndex, int days,
        const std::string& extensions = "",
        const std::string& primaryContext = "")
    {
        TempDir td;
        std::string primaryCtx =
            primaryContext.empty() ? td.path("primary.ctx") : primaryContext;

        // Always create a fresh primary key — a context file from a different
        // invocation (or a different TempDir) cannot be reused across sessions.
        if (!std::filesystem::exists(primaryCtx))
        {
            auto ec = createTPMPrimaryKey(primaryCtx);
            if (ec)
                return ec;
        }

        // Create entity key
        std::string privBlob = td.path("entity_key.priv");
        std::string pubBlob = td.path("entity_key.pub");
        auto ec = createTPMKey(primaryCtx, privBlob, pubBlob);
        if (ec)
            return ec;

        // Load and persist
        ec = loadAndPersistTPMKey(primaryCtx, privBlob, pubBlob,
                                  persistentHandle);
        if (ec)
            return ec;

        // Generate CSR
        std::string csrFile = td.path("entity.csr");
        ec = generateCSRWithTPMKey(persistentHandle, subject, csrFile);
        if (ec)
            return ec;

        // Read CA cert from NV
        std::string caCertFile = td.path("ca_cert.pem");
        std::string readCmd = std::format(
            "tpm2_nvread -C o {} > {} 2>/dev/null", caNVIndex, caCertFile);
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(readCmd.c_str()) != 0)
        {
            LOG_ERROR("Failed to read CA cert from NV");
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }

        // Sign with CA
        std::string certFile = td.path("entity_cert.pem");
        ec = signCertificateWithTPMCA(csrFile, caCertFile, caHandle, certFile,
                                      days, extensions);
        if (ec)
            return ec;

        // Store in NV (td cleans up all temp files on scope exit)
        ec = storeCertificateInTPMNV(certFile, nvIndex);
        if (ec)
            return ec;

        LOG_INFO("Entity certificate created in TPM: {} / {}", persistentHandle,
                 nvIndex);
        return boost::system::error_code{};
    }

    /**
     * @brief Create entity certificate signed by a filesystem CA (Simics mode)
     *
     * Generates the entity key inside the TPM, builds a CSR from it and signs
     * the CSR with the provisioned CA key/cert held on the filesystem (plain
     * openssl, no TPM provider needed).  The signed cert is stored in nvIndex.
     *
     * @param persistentHandle TPM handle for entity key
     * @param nvIndex NV index for entity cert
     * @param subject Entity subject
     * @param caKeyFile Filesystem path to the provisioned CA private key
     * @param caCertFile Filesystem path to the provisioned CA certificate
     * @param extensions Certificate extensions section ("v3_server" or
     * "v3_client")
     * @param primaryContext Primary key context file
     * @return error_code indicating success or failure
     */
    boost::system::error_code createEntityCertificateSignedByFilesystemCA(
        const std::string& persistentHandle, const std::string& nvIndex,
        const std::string& subject, const std::string& caKeyFile,
        const std::string& caCertFile, const std::string& extensions,
        const std::string& primaryContext = "")
    {
        TempDir td;
        std::string primaryCtx =
            primaryContext.empty() ? td.path("primary.ctx") : primaryContext;
        if (!std::filesystem::exists(primaryCtx))
        {
            auto ec = createTPMPrimaryKey(primaryCtx);
            if (ec)
                return ec;
        }

        // Create entity key
        std::string privBlob = td.path("entity_key.priv");
        std::string pubBlob = td.path("entity_key.pub");
        auto ec = createTPMKey(primaryCtx, privBlob, pubBlob);
        if (ec)
            return ec;

        // Load and persist
        ec = loadAndPersistTPMKey(primaryCtx, privBlob, pubBlob,
                                  persistentHandle);
        if (ec)
            return ec;

        // Generate CSR
        std::string csrFile = td.path("entity.csr");
        ec = generateCSRWithTPMKey(persistentHandle, subject, csrFile);
        if (ec)
            return ec;

        // Sign with the filesystem CA key
        // Generate a cryptographically secure random serial number
        uint64_t serial = 0;
        std::array<unsigned char, sizeof(serial)> serialBytes{};
        RAND_bytes(serialBytes.data(), static_cast<int>(serialBytes.size()));
        std::memcpy(&serial, serialBytes.data(), sizeof(serial));
        auto notBefore = certNotBefore();
        auto notAfter = certNotAfter();
        std::string extFile = td.path("cert_ext_fs_ca_sign.cnf");
        writeEntityExtFile(extFile, extensions);

        std::string certFile = td.path("entity_cert.pem");
        ec = executeTPMCommand(
            "openssl x509 -req -in {} -CA {} -CAkey {} -passin pass:"
            " -set_serial {} -out {} -not_before {} -not_after {}"
            " -extfile {} -extensions {} 2>&1",
            csrFile, caCertFile, caKeyFile, serial, certFile, notBefore,
            notAfter, extFile, extensions);
        if (ec)
        {
            LOG_ERROR("Failed to sign entity CSR with filesystem CA key");
            return ec;
        }

        // Store in NV (td cleans up all temp files on scope exit)
        ec = storeCertificateInTPMNV(certFile, nvIndex);
        if (ec)
            return ec;

        LOG_INFO("Entity certificate signed by filesystem CA: {} / {}",
                 persistentHandle, nvIndex);
        return boost::system::error_code{};
    }

    /**
     * @brief Create Boost.Asio SSL server context with TPM-backed certificate
     * and key
     * @param serverKeyHandle TPM persistent handle for server key (e.g.,
     * "0x81000002")
     * @param serverCertNV NV index for server certificate (e.g., "0x1500004")
     * @param serverCaCertNV NV index for server CA certificate to attach to
     * certificate chain (e.g., "0x1500003")
     * @param trustStoreCaCertNV NV index for CA certificate used as truststore
     * for client verification (e.g., "0x1500002")
     * @param requireClientCert Whether to require and verify client
     * certificates
     * @return std::pair<error_code, ssl::context>
     */
    std::pair<boost::system::error_code, boost::asio::ssl::context>
        createServerSSLContext(
            const std::string& serverKeyHandle, const std::string& serverCertNV,
            const std::string& serverCaCertNV,
            const std::string& trustStoreCaCertNV, bool requireClientCert)
    {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_server);

        // Configure the context for modern, secure operation
        ctx.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::no_tlsv1 |
                        boost::asio::ssl::context::no_tlsv1_1 |
                        boost::asio::ssl::context::single_dh_use);

        // Load server certificate from TPM NV
        X509Ptr serverCert(nullptr, &X509_free);
        auto ec = readCertificateFromTPMNV(serverCertNV, serverCert);
        if (ec)
        {
            LOG_ERROR("Failed to load server certificate from NV {}",
                      serverCertNV);
            return {ec, std::move(ctx)};
        }

        // Load server private key from TPM
        std::string keyUri = std::format("handle:{}", serverKeyHandle);
        EVP_PKEYPtr serverKey(nullptr, &EVP_PKEY_free);
        ec = loadPrivateKeyFromTpm(keyUri, serverKey);
        if (ec)
        {
            LOG_ERROR("Failed to load server key from handle {}",
                      serverKeyHandle);
            return {ec, std::move(ctx)};
        }

        // Configure SSL context
        SSL_CTX* nativeCtx = ctx.native_handle();

        // RSA keys on TPM hardware without RSAPSS support cannot sign TLS 1.3
        // CertificateVerify or TLS 1.2 RSAPSS; restrict to TLS 1.2 with PKCS#1
        // v1.5 sigalgs
        if (!isEccSupported())
        {
            ctx.set_options(boost::asio::ssl::context::no_tlsv1_3);
            SSL_CTX_set_max_proto_version(nativeCtx, TLS1_2_VERSION);
            SSL_CTX_set1_sigalgs_list(nativeCtx,
                                      "RSA+SHA256:RSA+SHA384:RSA+SHA512");
            SSL_CTX_set1_client_sigalgs_list(
                nativeCtx, "RSA+SHA256:RSA+SHA384:RSA+SHA512");
        }

        // Set server certificate
        if (SSL_CTX_use_certificate(nativeCtx, serverCert.get()) != 1)
        {
            LOG_ERROR("Failed to set server certificate");
            return {boost::system::errc::make_error_code(
                        boost::system::errc::invalid_argument),
                    std::move(ctx)};
        }

        // Load and add server CA certificate to the server certificate chain
        // This is needed because we only store leaf certificates in TPM
        X509Ptr serverCaCert(nullptr, &X509_free);
        ec = readCertificateFromTPMNV(serverCaCertNV, serverCaCert);
        if (ec)
        {
            LOG_WARNING(
                "Failed to load server CA certificate from NV {} for chain, continuing without chain",
                serverCaCertNV);
        }
        else
        {
            // Add server CA certificate to the certificate chain
            if (SSL_CTX_add_extra_chain_cert(nativeCtx, serverCaCert.get()) !=
                1)
            {
                LOG_WARNING(
                    "Failed to add server CA certificate to server chain");
            }
            else
            {
                // SSL_CTX_add_extra_chain_cert takes ownership, so release it
                std::ignore = serverCaCert.release();
                LOG_DEBUG(
                    "Added server CA certificate to server certificate chain");
            }
        }

        // Set server private key
        if (SSL_CTX_use_PrivateKey(nativeCtx, serverKey.get()) != 1)
        {
            LOG_ERROR("Failed to set server private key");
            return {boost::system::errc::make_error_code(
                        boost::system::errc::invalid_argument),
                    std::move(ctx)};
        }

        // Verify private key matches certificate
        if (SSL_CTX_check_private_key(nativeCtx) != 1)
        {
            LOG_ERROR("Server private key does not match certificate");
            return {boost::system::errc::make_error_code(
                        boost::system::errc::invalid_argument),
                    std::move(ctx)};
        }

        // Load truststore CA certificate for client verification
        if (requireClientCert)
        {
            X509Ptr trustStoreCaCert(nullptr, &X509_free);
            ec = readCertificateFromTPMNV(trustStoreCaCertNV, trustStoreCaCert);
            if (ec)
            {
                LOG_ERROR("Failed to load truststore CA certificate from NV {}",
                          trustStoreCaCertNV);
                return {ec, std::move(ctx)};
            }

            X509_STORE* store = SSL_CTX_get_cert_store(nativeCtx);
            if (X509_STORE_add_cert(store, trustStoreCaCert.get()) != 1)
            {
                LOG_ERROR(
                    "Failed to add truststore CA certificate to trust store");
                return {boost::system::errc::make_error_code(
                            boost::system::errc::invalid_argument),
                        std::move(ctx)};
            }

            // Require and verify client certificate
            ctx.set_verify_mode(boost::asio::ssl::verify_peer |
                                boost::asio::ssl::verify_fail_if_no_peer_cert);

            LOG_INFO(
                "Server SSL context configured with client certificate verification");
        }
        else
        {
            LOG_INFO(
                "Server SSL context configured without client certificate verification");
        }

        return {boost::system::error_code{}, std::move(ctx)};
    }

    /**
     * @brief Create Boost.Asio SSL client context with TPM-backed certificate
     * and key
     * @param clientKeyHandle TPM persistent handle for client key (e.g.,
     * "0x81000003")
     * @param clientCertNV NV index for client certificate (e.g., "0x1500006")
     * @param clientCaCertNV NV index for client CA certificate to attach to
     * certificate chain (e.g., "0x1500003")
     * @param trustStoreCaCertNV NV index for CA certificate used as truststore
     * for server verification (e.g., "0x1500002")
     * @param verifyServer Whether to verify server certificate
     * @return std::pair<error_code, ssl::context>
     */
    std::pair<boost::system::error_code, boost::asio::ssl::context>
        createClientSSLContext(
            const std::string& clientKeyHandle, const std::string& clientCertNV,
            const std::string& clientCaCertNV,
            const std::string& trustStoreCaCertNV, bool verifyServer)
    {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
        ctx.set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::no_tlsv1 |
                        boost::asio::ssl::context::no_tlsv1_1);
        // Load client certificate from TPM NV
        X509Ptr clientCert(nullptr, &X509_free);
        auto ec = readCertificateFromTPMNV(clientCertNV, clientCert);
        if (ec)
        {
            LOG_ERROR("Failed to load client certificate from NV {}",
                      clientCertNV);
            return {ec, std::move(ctx)};
        }

        // Load client private key from TPM
        std::string keyUri = std::format("handle:{}", clientKeyHandle);
        EVP_PKEYPtr clientKey(nullptr, &EVP_PKEY_free);
        ec = loadPrivateKeyFromTpm(keyUri, clientKey);
        if (ec)
        {
            LOG_ERROR("Failed to load client key from handle {}",
                      clientKeyHandle);
            return {ec, std::move(ctx)};
        }

        // Configure SSL context
        SSL_CTX* nativeCtx = ctx.native_handle();

        // RSA keys on TPM hardware without RSAPSS support cannot sign TLS 1.3
        // CertificateVerify or TLS 1.2 RSAPSS; restrict to TLS 1.2 with PKCS#1
        // v1.5 sigalgs
        if (!isEccSupported())
        {
            ctx.set_options(boost::asio::ssl::context::no_tlsv1_3);
            SSL_CTX_set_max_proto_version(nativeCtx, TLS1_2_VERSION);
            SSL_CTX_set1_sigalgs_list(nativeCtx,
                                      "RSA+SHA256:RSA+SHA384:RSA+SHA512");
        }

        // Set client certificate
        if (SSL_CTX_use_certificate(nativeCtx, clientCert.get()) != 1)
        {
            LOG_ERROR("Failed to set client certificate");
            return {boost::system::errc::make_error_code(
                        boost::system::errc::invalid_argument),
                    std::move(ctx)};
        }

        // Load and add client CA certificate to the client certificate chain
        // This is needed because we only store leaf certificates in TPM
        X509Ptr clientCaCert(nullptr, &X509_free);
        ec = readCertificateFromTPMNV(clientCaCertNV, clientCaCert);
        if (ec)
        {
            LOG_WARNING(
                "Failed to load client CA certificate from NV {} for chain, continuing without chain",
                clientCaCertNV);
        }
        else
        {
            // Add client CA certificate to the certificate chain
            if (SSL_CTX_add_extra_chain_cert(nativeCtx, clientCaCert.get()) !=
                1)
            {
                LOG_WARNING(
                    "Failed to add client CA certificate to client chain");
            }
            else
            {
                // SSL_CTX_add_extra_chain_cert takes ownership, so release it
                std::ignore = clientCaCert.release();
                LOG_DEBUG(
                    "Added client CA certificate to client certificate chain");
            }
        }

        // Set client private key
        if (SSL_CTX_use_PrivateKey(nativeCtx, clientKey.get()) != 1)
        {
            LOG_ERROR("Failed to set client private key");
            return {boost::system::errc::make_error_code(
                        boost::system::errc::invalid_argument),
                    std::move(ctx)};
        }

        // Verify private key matches certificate
        if (SSL_CTX_check_private_key(nativeCtx) != 1)
        {
            LOG_ERROR("Client private key does not match certificate");
            return {boost::system::errc::make_error_code(
                        boost::system::errc::invalid_argument),
                    std::move(ctx)};
        }

        // Load truststore CA certificate for server verification
        if (verifyServer)
        {
            X509Ptr trustStoreCaCert(nullptr, &X509_free);
            ec = readCertificateFromTPMNV(trustStoreCaCertNV, trustStoreCaCert);
            if (ec)
            {
                LOG_ERROR("Failed to load truststore CA certificate from NV {}",
                          trustStoreCaCertNV);
                return {ec, std::move(ctx)};
            }

            X509_STORE* store = SSL_CTX_get_cert_store(nativeCtx);
            if (X509_STORE_add_cert(store, trustStoreCaCert.get()) != 1)
            {
                LOG_ERROR(
                    "Failed to add truststore CA certificate to trust store");
                return {boost::system::errc::make_error_code(
                            boost::system::errc::invalid_argument),
                        std::move(ctx)};
            }

            // Verify server certificate
            ctx.set_verify_mode(boost::asio::ssl::verify_peer);

            LOG_INFO(
                "Client SSL context configured with server certificate verification");
        }
        else
        {
            LOG_INFO(
                "Client SSL context configured without server certificate verification");
        }

        return {boost::system::error_code{}, std::move(ctx)};
    }

    /**
     * @brief Create mTLS server context with TPM-backed certificates
     * Convenience wrapper that enables client certificate verification
     * @param serverKeyHandle TPM handle for server key
     * @param serverCertNV NV index for server certificate
     * @param serverCaCertNV NV index for server CA certificate (for chain)
     * @param trustStoreCaCertNV NV index for CA certificate (for truststore)
     * @param method SSL method (default: tls_server)
     * @return std::pair<error_code, ssl::context>
     */
    std::pair<boost::system::error_code, boost::asio::ssl::context>
        createMTLSServerContext(const std::string& serverKeyHandle,
                                const std::string& serverCertNV,
                                const std::string& serverCaCertNV,
                                const std::string& trustStoreCaCertNV)
    {
        return createServerSSLContext(serverKeyHandle, serverCertNV,
                                      serverCaCertNV, trustStoreCaCertNV, true);
    }

    /**
     * @brief Create mTLS client context with TPM-backed certificates
     * Convenience wrapper that enables server certificate verification
     * @param clientKeyHandle TPM handle for client key
     * @param clientCertNV NV index for client certificate
     * @param clientCaCertNV NV index for client CA certificate (for chain)
     * @param trustStoreCaCertNV NV index for CA certificate (for truststore)
     * @param method SSL method (default: tls_client)
     * @return std::pair<error_code, ssl::context>
     */
    std::pair<boost::system::error_code, boost::asio::ssl::context>
        createMTLSClientContext(const std::string& clientKeyHandle,
                                const std::string& clientCertNV,
                                const std::string& clientCaCertNV,
                                const std::string& trustStoreCaCertNV)
    {
        return createClientSSLContext(clientKeyHandle, clientCertNV,
                                      clientCaCertNV, trustStoreCaCertNV, true);
    }
    /**
     * @brief Store certificate in TPM NV index
     * @param cert Certificate to store
     * @param certPath Path to certificate file
     * @param nvIndex NV index to store certificate
     * @return true if successful, false otherwise
     */
    bool storeCertificateInTPM(const X509Ptr& cert, const std::string& certPath,
                               const std::string& nvIndex)
    {
        if (!cert)
        {
            LOG_ERROR("Certificate pointer is null");
            return false;
        }

        if (!isInitialized())
        {
            LOG_WARNING("TPM2 provider not initialized, skipping TPM storage");
            return true; // Not a failure, just skip TPM storage
        }

        auto ec = storeCertificateInTPMNV(certPath, nvIndex);
        if (ec)
        {
            LOG_ERROR("Failed to store certificate in TPM NV index {}: {}",
                      nvIndex, ec.message());
            return false;
        }

        LOG_DEBUG("Certificate stored in TPM NV index: {}", nvIndex);
        return true;
    }

    /**
     * @brief Store private key file in TPM NV index
     * @param keyFilePath Path to private key file
     * @param nvIndex NV index to store key
     * @return true if successful, false otherwise
     */
    bool storePrivateKeyFileInTPMNV(const std::string& keyFilePath,
                                    const std::string& nvIndex)
    {
        if (!isInitialized())
        {
            LOG_WARNING(
                "TPM2 provider not initialized, skipping TPM NV key storage");
            return true; // Not a failure, just skip TPM storage
        }

        // Check if key file exists
        if (!std::filesystem::exists(keyFilePath))
        {
            LOG_WARNING("Key file {} not found, skipping NV storage",
                        keyFilePath);
            return true;
        }

        // Get the size of the key file
        size_t keySize = std::filesystem::file_size(keyFilePath);
        constexpr size_t MAX_TPM_NV_SIZE = 2048;

        if (keySize > MAX_TPM_NV_SIZE)
        {
            LOG_WARNING(
                "Key size ({} bytes) exceeds TPM NV limit, skipping NV storage",
                keySize);
            return true;
        }

        // Check if NV index already exists and delete it
        std::string checkCmd =
            std::format("tpm2_nvreadpublic {} 2>/dev/null", nvIndex);
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(checkCmd.c_str()) == 0)
        {
            LOG_DEBUG("NV index {} already exists, deleting it", nvIndex);
            std::string deleteCmd =
                std::format("tpm2_nvundefine {} 2>&1", nvIndex);
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            system(deleteCmd.c_str()); // Ignore errors
        }

        // Define NV index for the key
        std::string defineCmd = std::format(
            R"(tpm2_nvdefine {} -C o -s {} -a "ownerread|ownerwrite" 2>&1)",
            nvIndex, keySize);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(defineCmd.c_str()) != 0)
        {
            LOG_WARNING(
                "Failed to define TPM NV index {} for key, continuing...",
                nvIndex);
            return true;
        }

        // Write key to NV
        std::string writeCmd = std::format("tpm2_nvwrite {} -C o -i {} 2>&1",
                                           nvIndex, keyFilePath);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(writeCmd.c_str()) != 0)
        {
            LOG_WARNING("Failed to write key to TPM NV {}, continuing...",
                        nvIndex);
            return true;
        }

        LOG_INFO(
            "Private key from file {} stored in TPM NV index {} ({} bytes)",
            keyFilePath, nvIndex, keySize);
        return true;
    }

    /**
     * @brief Store private key in TPM NV index from persistent handle
     * @param persistentHandle TPM persistent handle containing the key
     * @param nvIndex NV index to store key
     * @return true if successful, false otherwise
     */
    bool storePrivateKeyInTPMNV(const char* persistentHandle,
                                const std::string& nvIndex)
    {
        if (!isInitialized())
        {
            LOG_WARNING(
                "TPM2 provider not initialized, skipping TPM NV key storage");
            return true; // Not a failure, just skip TPM storage
        }

        TempDir td;
        // Export the private key from persistent handle to a temporary file
        std::string tempKeyFile = td.path("key.priv.pem");
        std::string tempPubFile = td.path("key.pub");

        // Use tpm2_readpublic to export the public portion
        std::string exportCmd = std::format(
            "tpm2_readpublic -c {} -o {} 2>&1 && "
            "tpm2_print -t TPM2B_PUBLIC {} > {} 2>&1",
            persistentHandle, tempPubFile, tempPubFile, tempKeyFile);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(exportCmd.c_str()) != 0)
        {
            LOG_WARNING("Failed to export key from handle {} for NV storage, "
                        "continuing...",
                        persistentHandle);
            return true; // Not critical, continue
        }

        // Get the size of the key file
        if (!std::filesystem::exists(tempKeyFile))
        {
            LOG_WARNING("Key file not found after export, skipping NV storage");
            return true;
        }

        size_t keySize = std::filesystem::file_size(tempKeyFile);
        constexpr size_t MAX_TPM_NV_SIZE = 2048;

        if (keySize > MAX_TPM_NV_SIZE)
        {
            LOG_WARNING(
                "Key size ({} bytes) exceeds TPM NV limit, skipping NV storage",
                keySize);
            return true;
        }

        // Check if NV index already exists and delete it
        std::string checkCmd =
            std::format("tpm2_nvreadpublic {} 2>/dev/null", nvIndex);
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(checkCmd.c_str()) == 0)
        {
            LOG_DEBUG("NV index {} already exists, deleting it", nvIndex);
            std::string deleteCmd =
                std::format("tpm2_nvundefine {} 2>&1", nvIndex);
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            system(deleteCmd.c_str()); // Ignore errors
        }

        // Define NV index for the key
        std::string defineCmd = std::format(
            R"(tpm2_nvdefine {} -C o -s {} -a "ownerread|ownerwrite" 2>&1)",
            nvIndex, keySize);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(defineCmd.c_str()) != 0)
        {
            LOG_WARNING(
                "Failed to define TPM NV index {} for key, continuing...",
                nvIndex);
            return true;
        }

        // Write key to NV
        std::string writeCmd = std::format("tpm2_nvwrite {} -C o -i {} 2>&1",
                                           nvIndex, tempKeyFile);

        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (system(writeCmd.c_str()) != 0)
        {
            LOG_WARNING("Failed to write key to TPM NV {}, continuing...",
                        nvIndex);
            return true;
        }

        // td destructor cleans up all temp files
        LOG_INFO(
            "Private key from handle {} stored in TPM NV index {} ({} bytes)",
            persistentHandle, nvIndex, keySize);
        return true;
    }

    /**
     * @brief Create private key directly in TPM as persistent object
     * @param persistentHandle TPM persistent handle for the key
     * @param nvIndex Optional NV index to also store the key
     * @param primaryCtxPath Path for primary context file
     * @return true if successful, false otherwise
     */
    bool createPrivateKeyInTPM(const char* persistentHandle,
                               const std::string& nvIndex = "",
                               const std::string& primaryCtxPath = "")
    {
        if (!isInitialized())
        {
            LOG_WARNING(
                "TPM2 provider not initialized, skipping TPM key creation");
            return true; // Not a failure, just skip TPM storage
        }

        TempDir td;
        std::string primaryCtx = primaryCtxPath.empty()
                                     ? td.path("primary_tpm.ctx")
                                     : primaryCtxPath;

        // Step 1: Create TPM primary key
        auto ec = createTPMPrimaryKey(primaryCtx);
        if (ec)
        {
            LOG_ERROR("Failed to create TPM primary key: {}", ec.message());
            return false;
        }

        // Step 2: Create TPM key as child of primary
        std::string privFile = td.path("key.priv");
        std::string pubFile = td.path("key.pub");

        ec = createTPMKey(primaryCtx, privFile, pubFile);
        if (ec)
        {
            LOG_ERROR("Failed to create TPM key: {}", ec.message());
            return false;
        }

        // Step 3: Load and persist the TPM key (td cleans up on scope exit)
        ec = loadAndPersistTPMKey(primaryCtx, privFile, pubFile,
                                  persistentHandle);

        if (ec)
        {
            LOG_ERROR("Failed to persist TPM key at handle {}: {}",
                      persistentHandle, ec.message());
            return false;
        }

        LOG_DEBUG("Private key created in TPM persistent handle: {}",
                  persistentHandle);

        // Step 4: Store the key in NV index if requested
        if (!nvIndex.empty())
        {
            if (!storePrivateKeyInTPMNV(persistentHandle, nvIndex))
            {
                LOG_WARNING("Failed to store key in NV index {}, continuing...",
                            nvIndex);
            }
        }

        return true;
    }

    /**
     * @brief Create certificate using TPM key via TPM2 provider
     * @param tpmKeyHandle TPM key handle
     * @param subject Certificate subject
     * @param caCertPath Path to CA certificate (empty for self-signed)
     * @param caKeyHandle CA key handle (empty for self-signed)
     * @param daysValid Certificate validity in days
     * @param isCA Whether this is a CA certificate
     * @param isServer Whether this is a server certificate (vs client)
     * @return Optional X509Ptr containing the certificate
     */
    std::optional<X509Ptr> createCertificateWithTPMKey(
        const std::string& tpmKeyHandle, const std::string& subject,
        const std::string& caCertPath = "", const std::string& caKeyHandle = "",
        int daysValid = 365, bool isCA = false, bool isServer = true)
    {
        if (!isInitialized())
        {
            LOG_ERROR("TPM2 provider not initialized");
            return std::nullopt;
        }

        TempDir td;
        // Generate CSR using TPM key
        std::string csrFile = td.path("cert.csr");
        auto ec = generateCSRWithTPMKey(tpmKeyHandle, subject, csrFile);
        if (ec)
        {
            LOG_ERROR("Failed to generate CSR with TPM key {}: {}",
                      tpmKeyHandle, ec.message());
            return std::nullopt;
        }

        // Sign certificate
        std::string certFile = td.path("cert.pem");

        if (isCA || caCertPath.empty())
        {
            // Self-sign for CA certificate
            ec = selfSignCertificateWithTPM(csrFile, tpmKeyHandle, certFile,
                                            daysValid, isCA ? "v3_ca" : "");
        }
        else
        {
            // Sign with CA - use appropriate extension based on certificate
            // type Use v3_server for server certs, empty string for client
            // certs (uses default)
            const char* extension = isServer ? "v3_server" : "";
            ec = signCertificateWithTPMCA(csrFile, caCertPath, caKeyHandle,
                                          certFile, daysValid, extension);
        }

        if (ec)
        {
            LOG_ERROR("Failed to sign certificate: {}", ec.message());
            return std::nullopt;
        }

        // Load the certificate (td cleans up on scope exit)
        auto cert = loadCertificate(certFile);

        if (!cert)
        {
            LOG_ERROR("Failed to load signed certificate");
            return std::nullopt;
        }

        LOG_DEBUG("Certificate created with TPM key: {}", tpmKeyHandle);
        return cert;
    }
};

} // namespace NSNAME
