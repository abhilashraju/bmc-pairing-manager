#pragma once
#include "cert_generator.hpp"
#include "eventmethods.hpp"
#include "eventqueue.hpp"
#include "globaldefs.hpp"
#include "tpm2_cert_manager.hpp"
#include "tpm_handles.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
using namespace NSNAME;
constexpr auto INSTALL_CERTIFICATES = "InstallCertificates";
constexpr auto INSTALL_CERTIFICATES_RESP = "InstallCertificatesResp";

// ---------------------------------------------------------------------------
// TPM NV / handle constants — sourced from the shared tpm_handles.hpp.
// Local aliases keep existing code in this file unchanged.
// ---------------------------------------------------------------------------
inline constexpr const char* ATTEST_TPM_CA_KEY_HANDLE = TPM_CA_KEY_HANDLE;
inline constexpr const char* ATTEST_TPM_CA_CERT_NV = TPM_PEER_ROOT_CA_CERT_NV;
// Peer CA received during certificate exchange — written by
// installCertificates. bmc-pairing-manager reads TPM_TRUSTSTORE_CA_CERT_NV
// from here.
inline constexpr const char* ATTEST_TPM_TRUSTSTORE_CA_CERT_NV =
    TPM_TRUSTSTORE_CA_CERT_NV;
inline constexpr const char* ATTEST_TPM_SERVER_KEY_HANDLE =
    TPM_SERVER_KEY_HANDLE;
inline constexpr const char* ATTEST_TPM_SERVER_CERT_NV = TPM_SERVER_CERT_NV;
inline constexpr const char* ATTEST_TPM_CLIENT_KEY_HANDLE =
    TPM_CLIENT_KEY_HANDLE;
inline constexpr const char* ATTEST_TPM_CLIENT_CERT_NV = TPM_CLIENT_CERT_NV;

using ENTITY_DATA =
    std::tuple<const char*, std::string, std::string, std::string>;

// Helper function to create certificate hash file for trust store
inline bool createCertificateHashFile(const X509Ptr& cert,
                                      const std::string& certPath)
{
    if (!cert)
    {
        LOG_ERROR("Certificate pointer is null");
        return false;
    }

    // Calculate the certificate hash using X509_subject_name_hash
    unsigned long hash = X509_subject_name_hash(cert.get());

    // Get the directory path where the certificate is stored
    std::filesystem::path certFilePath(certPath);
    std::filesystem::path certDir = certFilePath.parent_path();

    // Format hash as 8-digit hex string
    std::ostringstream hashStream;
    hashStream << std::hex << std::setw(8) << std::setfill('0') << hash;
    std::string hashStr = hashStream.str();

    // Find the next available index for this hash (handle collisions)
    int index = 0;
    std::filesystem::path hashFilePath;
    do
    {
        hashFilePath = certDir / (hashStr + "." + std::to_string(index));
        index++;
    } while (std::filesystem::exists(hashFilePath) && index < 100);

    if (index >= 100)
    {
        LOG_ERROR("Too many hash collisions for certificate hash {}", hashStr);
        return false;
    }

    // Create symlink from hash file to actual certificate
    std::error_code ec;
    std::filesystem::create_symlink(certFilePath.filename(), hashFilePath, ec);
    if (ec)
    {
        LOG_ERROR("Failed to create hash symlink {} -> {}: {}",
                  hashFilePath.string(), certFilePath.string(), ec.message());
        return false;
    }

    LOG_DEBUG("Created certificate hash file: {} -> {}", hashFilePath.string(),
              certFilePath.string());
    return true;
}

// Helper function to verify trust store directory is usable
inline bool verifyTrustStorePath(const std::string& dirPath)
{
    namespace fs = std::filesystem;

    if (!fs::exists(dirPath))
    {
        LOG_ERROR("Trust store directory does not exist: {}", dirPath);
        return false;
    }

    if (!fs::is_directory(dirPath))
    {
        LOG_ERROR("Trust store path is not a directory: {}", dirPath);
        return false;
    }

    // Check if directory is readable
    std::error_code ec;
    auto perms = fs::status(dirPath, ec).permissions();
    if (ec)
    {
        LOG_ERROR("Failed to get permissions for {}: {}", dirPath,
                  ec.message());
        return false;
    }

    // Check for read and execute permissions (needed to access directory)
    if ((perms & fs::perms::owner_read) == fs::perms::none ||
        (perms & fs::perms::owner_exec) == fs::perms::none)
    {
        LOG_ERROR("Insufficient permissions for trust store directory: {}",
                  dirPath);
        return false;
    }

    LOG_DEBUG("Trust store directory verified: {}", dirPath);
    return true;
}

// Helper function to save combined certificate and private key to a single file
inline bool saveCombinedCertAndKey(const X509Ptr& cert, const EVP_PKEYPtr& key,
                                   const std::string& filename)
{
    openssl_ptr<BIO, BIO_free_all> combined_bio(BIO_new(BIO_s_mem()),
                                                &BIO_free_all);

    // Write certificate to BIO
    if (!PEM_write_bio_X509(combined_bio.get(), cert.get()))
    {
        LOG_ERROR("Failed to write certificate to combined BIO");
        return false;
    }

    // Write private key to BIO
    if (!PEM_write_bio_PrivateKey(combined_bio.get(), key.get(), nullptr,
                                  nullptr, 0, nullptr, nullptr))
    {
        LOG_ERROR("Failed to write private key to combined BIO");
        return false;
    }

    if (!saveBio(filename, combined_bio))
    {
        LOG_ERROR("Failed to save combined certificate and key to {}",
                  filename);
        return false;
    }

    LOG_DEBUG("Combined certificate and private key saved to {}", filename);
    return true;
}

template <int COUNT>
std::optional<std::pair<X509Ptr, EVP_PKEYPtr>> createAndSaveEntityCertificate(
    const EVP_PKEYPtr& ca_pkey, const X509Ptr& ca,
    const std::string& common_name,
    const std::array<ENTITY_DATA, COUNT>& entity_data, int index,
    int days_valid = CERT_MAX_VALIDITY_DAYS)
{
    auto ca_name = openssl_ptr<X509_NAME, X509_NAME_free>(
        X509_NAME_dup(X509_get_subject_name(ca.get())), &X509_NAME_free);
    auto [cert, key] =
        create_leaf_cert(ca_pkey.get(), ca_name.get(), common_name, days_valid);
    if (!cert || !key)
    {
        LOG_ERROR("Failed to create entity certificate");
        return std::nullopt;
    }

    // Add serverAuth extended key usage
    // openssl_ptr<X509_EXTENSION, X509_EXTENSION_free> ext(
    //     X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage,
    //                         (char*)std::get<0>(entity_data[server])),
    //     X509_EXTENSION_free);
    // if (!ext)
    // {
    //     LOG_ERROR("Failed to add serverAuth extension");
    //     return std::nullopt;
    // }
    // X509_add_ext(cert.get(), ext.get(), -1);
    if (!savePrivateKey(std::get<1>(entity_data[index]), key))
    {
        LOG_ERROR("Failed to save private key to {}",
                  std::get<1>(entity_data[index]));
        return std::nullopt;
    }
    std::vector<X509*> cert_chain;
    cert_chain.emplace_back(cert.get());
    cert_chain.emplace_back(ca.get());
    std::string filename = std::get<2>(entity_data[index]);
    if (!saveCertificate(filename, cert_chain))
    {
        LOG_ERROR("Failed to save entity certificate to {}",
                  std::get<2>(entity_data[index]));
        return std::nullopt;
    }

    // Save combined certificate and private key file
    std::string combined_filename = std::get<3>(entity_data[index]);
    if (!saveCombinedCertAndKey(cert, key, combined_filename))
    {
        LOG_ERROR("Failed to save combined certificate and key to {}",
                  combined_filename);
        return std::nullopt;
    }

    LOG_DEBUG("Entity certificate and private key saved to {} and {}, "
              "combined file saved to {}",
              std::get<2>(entity_data[index]), std::get<1>(entity_data[index]),
              combined_filename);
    return std::make_optional(std::make_pair(std::move(cert), std::move(key)));
}

// Free function used by FileSystemCertStrategy (avoids forward-declaring
// CertificateExchanger before its full definition).
inline bool processInterMediateCACerts(
    const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
    const openssl_ptr<X509, X509_free>& ca, const std::string& hostName)
{
    if (!pkey)
    {
        LOG_ERROR("Failed to read private key from provided data");
        return false;
    }
    if (!ca)
    {
        LOG_ERROR("Failed to read CA certificate from provided data");
        return false;
    }
    std::array<ENTITY_DATA, 2> entityData = {
        ENTITY_DATA{"clientAuth", CLIENT_PKEY_PATH(), ENTITY_CLIENT_CERT_PATH(),
                    ENTITY_CLIENT_COMBINED_PATH()},
        ENTITY_DATA{"serverAuth", SERVER_PKEY_PATH(), ENTITY_SERVER_CERT_PATH(),
                    ENTITY_SERVER_COMBINED_PATH()}};
    auto servCert =
        createAndSaveEntityCertificate<2>(pkey, ca, hostName, entityData, 1);
    if (!servCert)
    {
        LOG_ERROR("Failed to create server entity certificate");
        return false;
    }
    auto clientCert =
        createAndSaveEntityCertificate<2>(pkey, ca, "service", entityData, 0);
    if (!clientCert)
    {
        LOG_ERROR("Failed to create client entity certificate");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Certificate creation strategy interface
// ---------------------------------------------------------------------------

/** Abstract strategy for creating/installing/loading the CA + entity certs. */
struct ICertificateStrategy
{
    virtual ~ICertificateStrategy() = default;
    ICertificateStrategy() = default;
    ICertificateStrategy(const ICertificateStrategy&) = default;
    ICertificateStrategy& operator=(const ICertificateStrategy&) = default;
    ICertificateStrategy(ICertificateStrategy&&) = default;
    ICertificateStrategy& operator=(ICertificateStrategy&&) = default;

    /**
     * @brief Create/refresh the CA and entity certificates.
     * @param hostName  Common-name used for the server entity certificate.
     * @return The loaded CA X509 certificate on success, nullptr on failure.
     */
    virtual X509Ptr create(const std::string& hostName) = 0;

    /**
     * @brief Install the peer CA received during certificate exchange.
     * @param castr  PEM encoded peer CA certificate.
     * @return true on success.
     */
    virtual bool install(const std::string& castr) = 0;

    /**
     * @brief Load the already-created local CA cert without regenerating
     *        any keys.
     * @return The CA X509 certificate on success, nullptr on failure.
     */
    virtual X509Ptr loadCa() = 0;
};

// ---------------------------------------------------------------------------
// FileSystem strategy — existing behaviour, unchanged
// ---------------------------------------------------------------------------

/**
 * Creates certificates from PEM files on the filesystem (the original
 * implementation).  The CA key lives at AUTHORITY_CA_KEY_PATH and entity
 * certs are written to the standard SSL paths.
 */
struct FileSystemCertStrategy : ICertificateStrategy
{
    bool install(const std::string& castr) override
    {
        openssl_ptr<BIO, BIO_free_all> bio(
            BIO_new_mem_buf(castr.data(), static_cast<int>(castr.size())),
            &BIO_free_all);
        openssl_ptr<X509, X509_free> ca(
            PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr),
            &X509_free);

        if (!saveCertificate(CA_PATH(), ca))
        {
            LOG_ERROR("Failed to save CA certificate to {}", CA_PATH());
            return false;
        }
        LOG_DEBUG("CA Certificates written to {} ", CA_PATH());

        // Create certificate hash file for trust store usage
        if (!createCertificateHashFile(ca, CA_PATH()))
        {
            LOG_ERROR("Failed to create certificate hash file for {}",
                      CA_PATH());
            return false;
        }

        // Verify that the directory can be used as a trust store path
        std::filesystem::path caPath(CA_PATH());
        std::string trustStoreDir = caPath.parent_path().string();
        if (!verifyTrustStorePath(trustStoreDir))
        {
            LOG_ERROR("Trust store directory verification failed: {}",
                      trustStoreDir);
            return false;
        }

        LOG_DEBUG(
            "Certificate hash file created and trust store verified for {}",
            trustStoreDir);
        return true;
    }

    X509Ptr loadCa() override
    {
        auto caCert = loadCertificate(AUTHORITY_CA_CERT_PATH);
        if (!caCert)
        {
            LOG_ERROR("loadCa: failed to load CA cert from {}",
                      AUTHORITY_CA_CERT_PATH);
        }
        return caCert;
    }

    X509Ptr create(const std::string& hostName) override
    {
        // Simics: every BMC shares the CA shipped in the image.
        // Device: every BMC owns a unique self-signed CA.
        const bool caReady =
            isSimics() ? seedCAIntoSslPaths() : generateSelfSignedCA();
        if (!caReady || !publishCA())
        {
            LOG_ERROR("Failed to ensure CA is available in SSL paths");
            return makeX509Ptr(nullptr);
        }

        auto caCert = loadCertificate(AUTHORITY_CA_CERT_PATH);
        if (!caCert)
        {
            LOG_ERROR("Failed to load CA certificate from {}",
                      AUTHORITY_CA_CERT_PATH);
            return makeX509Ptr(nullptr);
        }

        auto caPkey = loadPrivateKey(AUTHORITY_CA_KEY_PATH);
        if (!caPkey)
        {
            LOG_ERROR("Failed to load CA private key from {}",
                      AUTHORITY_CA_KEY_PATH);
            return makeX509Ptr(nullptr);
        }

        if (!processInterMediateCACerts(caPkey, caCert, hostName))
        {
            LOG_ERROR("Failed to process intermediate CA");
            return makeX509Ptr(nullptr);
        }
        return caCert;
    }

  private:
    static bool createAuthorityDirectories()
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::create_directories(fs::path(AUTHORITY_CA_CERT_PATH).parent_path(),
                               ec);
        if (ec)
        {
            LOG_ERROR("Failed to create authority directory: {}", ec.message());
            return false;
        }
        fs::create_directories(fs::path(AUTHORITY_CA_KEY_PATH).parent_path(),
                               ec);
        if (ec)
        {
            LOG_ERROR("Failed to create private key directory: {}",
                      ec.message());
            return false;
        }
        fs::create_directories(
            fs::path(std::format(SELF_CA_PATH_X, "/")).parent_path(), ec);
        if (ec)
        {
            LOG_ERROR("Failed to create certs directory: {}", ec.message());
            return false;
        }
        return true;
    }

    // Simics only, on every startup:
    //   1. Seed /var/attestation/ca.* from the image defaults.
    //   2. Copy /var/attestation/ca.* into /etc/ssl paths (wiped on each
    //      reflash).
    static bool seedCAIntoSslPaths()
    {
        namespace fs = std::filesystem;

        if (!seedProvisionedCA() || !createAuthorityDirectories())
        {
            return false;
        }

        if (!copyFile(PROVISIONED_CA_CERT_PATH, AUTHORITY_CA_CERT_PATH,
                      fs::perms::owner_read | fs::perms::owner_write |
                          fs::perms::group_read | fs::perms::others_read))
        {
            return false;
        }
        LOG_INFO("CA certificate promoted to {}", AUTHORITY_CA_CERT_PATH);

        if (!copyFile(PROVISIONED_CA_KEY_PATH, AUTHORITY_CA_KEY_PATH,
                      fs::perms::owner_read | fs::perms::owner_write))
        {
            return false;
        }
        LOG_INFO("CA private key promoted to {}", AUTHORITY_CA_KEY_PATH);
        return true;
    }

    // Device only: generate a unique self-signed CA for this BMC.  An existing
    // CA/key pair is reused so the CA already given to the peer stays valid
    // across restarts; /etc is wiped on reflash, which yields a new CA.
    static bool generateSelfSignedCA()
    {
        namespace fs = std::filesystem;

        if (!createAuthorityDirectories())
        {
            return false;
        }

        if (fs::exists(AUTHORITY_CA_CERT_PATH) &&
            fs::exists(AUTHORITY_CA_KEY_PATH) &&
            loadCertificate(AUTHORITY_CA_CERT_PATH) &&
            loadPrivateKey(AUTHORITY_CA_KEY_PATH))
        {
            LOG_INFO("Reusing existing self-signed CA at {}",
                     AUTHORITY_CA_CERT_PATH);
            return true;
        }

        auto [ca,
              pkey] = create_ca_cert(nullptr, nullptr, "BMC Attestation CA");
        if (!ca || !pkey)
        {
            LOG_ERROR("Failed to generate self-signed CA certificate");
            return false;
        }
        if (!saveCertificate(AUTHORITY_CA_CERT_PATH, ca) ||
            !savePrivateKey(AUTHORITY_CA_KEY_PATH, pkey))
        {
            LOG_ERROR("Failed to save self-signed CA to {} / {}",
                      AUTHORITY_CA_CERT_PATH, AUTHORITY_CA_KEY_PATH);
            return false;
        }
        std::error_code ec;
        fs::permissions(AUTHORITY_CA_CERT_PATH,
                        fs::perms::owner_read | fs::perms::owner_write |
                            fs::perms::group_read | fs::perms::others_read,
                        ec);
        fs::permissions(AUTHORITY_CA_KEY_PATH,
                        fs::perms::owner_read | fs::perms::owner_write, ec);
        LOG_INFO("Generated unique self-signed CA at {}",
                 AUTHORITY_CA_CERT_PATH);
        return true;
    }

    // Common to both modes, once the CA exists at AUTHORITY_CA_*_PATH:
    //   1. Place a copy of the CA cert at the exchange path (self_ca.pem).
    //   2. Create the OpenSSL hash symlink in the authority directory.
    static bool publishCA()
    {
        namespace fs = std::filesystem;
        std::error_code ec;

        const std::string selfCaPath = std::format(SELF_CA_PATH_X, "/");
        if (!copyFile(AUTHORITY_CA_CERT_PATH, selfCaPath,
                      fs::perms::owner_read | fs::perms::owner_write |
                          fs::perms::group_read | fs::perms::others_read))
        {
            return false;
        }
        LOG_INFO("CA certificate copy placed at {}", selfCaPath);

        // Create OpenSSL hash symlink in the authority directory so that
        // SSL_CTX_set_verify_path / add_verify_path can resolve the CA.
        auto ca = loadCertificate(AUTHORITY_CA_CERT_PATH);
        if (!ca)
        {
            LOG_ERROR("Failed to load CA cert for hash link generation");
            return false;
        }
        unsigned long hash = X509_subject_name_hash(ca.get());
        std::ostringstream oss;
        oss << std::hex << std::setw(8) << std::setfill('0') << hash;
        const fs::path authorityDir =
            fs::path(AUTHORITY_CA_CERT_PATH).parent_path();
        // Find first free index.
        int idx = 0;
        fs::path hashLink;
        do
        {
            hashLink = authorityDir / (oss.str() + "." + std::to_string(idx));
            idx++;
        } while (fs::exists(hashLink) && idx < 100);

        if (!fs::exists(hashLink))
        {
            fs::create_symlink(fs::path(AUTHORITY_CA_CERT_PATH).filename(),
                               hashLink, ec);
            if (ec)
            {
                LOG_ERROR("Failed to create hash symlink {}: {}",
                          hashLink.string(), ec.message());
                return false;
            }
            LOG_INFO("Created trust-store hash symlink {}", hashLink.string());
        }

        return true;
    }
};

// ---------------------------------------------------------------------------
// TPM strategy — creates CA + entity certs backed by the TPM
// ---------------------------------------------------------------------------

/**
 * Creates certificates whose private keys are held inside the TPM.
 *
 * Simics mode: the provisioned CA (PROVISIONED_CA_CERT/KEY_PATH) signs the
 * server and client entity certificates directly.  The provisioned CA cert is
 * stored in both ATTEST_TPM_CA_CERT_NV and ATTEST_TPM_TRUSTSTORE_CA_CERT_NV.
 *
 * Non-Simics mode: a new self-signed CA is generated with a TPM key at
 * ATTEST_TPM_CA_KEY_HANDLE and its cert stored at ATTEST_TPM_CA_CERT_NV.
 * It signs the server and client entity certificates.
 * ATTEST_TPM_TRUSTSTORE_CA_CERT_NV is left empty until a peer CA is
 * installed by the certificate exchange.
 *
 * Entity keys/certs are placed at the handles and NV indices that match the
 * constants used by ssl_functions.hpp (ATTEST_TPM_SERVER_* /
 * ATTEST_TPM_CLIENT_*).
 *
 * After all TPM objects are created the CA cert is exported from TPM NV into
 * the standard filesystem SSL paths so that the rest of the daemon (which
 * calls loadCertificate) continues to work.
 */
struct TpmCertStrategy : ICertificateStrategy
{
    // The peer CA is stored only in TPM NV (TPM_TRUSTSTORE_CA_CERT_NV), which
    // is where bmc-pairing-manager reads its trust store from.  Nothing is
    // installed in the filesystem trust store.
    bool install(const std::string& castr) override
    {
        auto& tpm = Tpm2CertManager::getInstance();
        if (!tpm.isInitialized())
        {
            LOG_ERROR("TPM2 provider not initialized; cannot install peer CA");
            return false;
        }

        // storeCertificateInTPMNV takes a file path; stage the PEM in a
        // private (0700) temp directory that is removed on scope exit.
        Tpm2CertManager::TempDir td;
        const std::string tmpCa = td.path("peer_ca.pem");
        {
            std::ofstream out(tmpCa, std::ios::binary | std::ios::trunc);
            out << castr;
            if (!out)
            {
                LOG_ERROR("Failed to stage peer CA for TPM NV storage");
                return false;
            }
        }

        auto ec = tpm.storeCertificateInTPMNV(tmpCa,
                                              ATTEST_TPM_TRUSTSTORE_CA_CERT_NV);
        if (ec)
        {
            LOG_ERROR("Failed to store peer CA in TPM NV {}: {}",
                      ATTEST_TPM_TRUSTSTORE_CA_CERT_NV, ec.message());
            return false;
        }
        LOG_INFO("Peer CA stored in TPM NV {}",
                 ATTEST_TPM_TRUSTSTORE_CA_CERT_NV);
        return true;
    }

    X509Ptr loadCa() override
    {
        X509Ptr caCert(nullptr, &X509_free);
        auto ec = reactor::Tpm2CertManager::readCertificateFromTPMNV(
            ATTEST_TPM_CA_CERT_NV, caCert);
        if (ec)
        {
            LOG_ERROR("loadCa: failed to read CA cert from TPM NV {}: {}",
                      ATTEST_TPM_CA_CERT_NV, ec.message());
            return makeX509Ptr(nullptr);
        }
        LOG_DEBUG("loadCa: loaded CA cert from TPM NV {}",
                  ATTEST_TPM_CA_CERT_NV);
        return caCert;
    }

    X509Ptr create(const std::string& hostName) override
    {
        auto& tpm = Tpm2CertManager::getInstance();
        if (!tpm.isInitialized())
        {
            LOG_ERROR(
                "TPM2 provider not initialized; cannot use TpmCertStrategy");
            return makeX509Ptr(nullptr);
        }

        // ---------------------------------------------------------------
        // If all three NV indices already hold valid certs, skip creation
        // and return the CA cert directly.
        // ---------------------------------------------------------------
        if (allCertsPresent(tpm))
        {
            LOG_INFO(
                "TPM certificate strategy: all certs already present, skipping creation");
            return loadCaFromTpm();
        }

        const std::string entityName = hostName.empty() ? "bmc" : hostName;
        const std::string serverSubject = std::format("/CN={}", entityName);
        const std::string clientSubject = "/CN=service";

        boost::system::error_code ec;
        if (isSimics())
        {
            // -----------------------------------------------------------
            // Simics: provisioned CA stored in the CA and trust-store NV
            // slots; it signs both entity certs directly.
            // -----------------------------------------------------------
            LOG_INFO("Simics mode: using provisioned CA to sign entity certs");
            ec = seedProvisionedCAIntoTPM(tpm);
            if (ec)
            {
                LOG_ERROR("TPM: failed to seed provisioned CA: {}",
                          ec.message());
                return makeX509Ptr(nullptr);
            }

            ec = tpm.createEntityCertificateSignedByFilesystemCA(
                ATTEST_TPM_SERVER_KEY_HANDLE, ATTEST_TPM_SERVER_CERT_NV,
                serverSubject, PROVISIONED_CA_KEY_PATH,
                PROVISIONED_CA_CERT_PATH, "v3_server");
            if (ec)
            {
                LOG_ERROR("TPM: failed to create server entity certificate: {}",
                          ec.message());
                return makeX509Ptr(nullptr);
            }

            ec = tpm.createEntityCertificateSignedByFilesystemCA(
                ATTEST_TPM_CLIENT_KEY_HANDLE, ATTEST_TPM_CLIENT_CERT_NV,
                clientSubject, PROVISIONED_CA_KEY_PATH,
                PROVISIONED_CA_CERT_PATH, "v3_client");
            if (ec)
            {
                LOG_ERROR("TPM: failed to create client entity certificate: {}",
                          ec.message());
                return makeX509Ptr(nullptr);
            }
        }
        else
        {
            // -----------------------------------------------------------
            // Non-Simics: new self-signed CA in the TPM CA slot signs both
            // entity certs.  The trust-store slot is not filled here.
            // -----------------------------------------------------------
            ec = tpm.createCACertificateInTPM(ATTEST_TPM_CA_KEY_HANDLE,
                                              ATTEST_TPM_CA_CERT_NV,
                                              "/CN=BMC-Attestation-CA", 3650);
            if (ec)
            {
                LOG_ERROR("TPM: failed to create CA certificate: {}",
                          ec.message());
                return makeX509Ptr(nullptr);
            }

            ec = tpm.createEntityCertificateInTPM(
                ATTEST_TPM_SERVER_KEY_HANDLE, ATTEST_TPM_SERVER_CERT_NV,
                serverSubject, ATTEST_TPM_CA_KEY_HANDLE, ATTEST_TPM_CA_CERT_NV,
                365, "v3_server");
            if (ec)
            {
                LOG_ERROR("TPM: failed to create server entity certificate: {}",
                          ec.message());
                return makeX509Ptr(nullptr);
            }

            ec = tpm.createEntityCertificateInTPM(
                ATTEST_TPM_CLIENT_KEY_HANDLE, ATTEST_TPM_CLIENT_CERT_NV,
                clientSubject, ATTEST_TPM_CA_KEY_HANDLE, ATTEST_TPM_CA_CERT_NV,
                365, "v3_client");
            if (ec)
            {
                LOG_ERROR("TPM: failed to create client entity certificate: {}",
                          ec.message());
                return makeX509Ptr(nullptr);
            }
        }

        LOG_INFO("TPM certificate strategy: CA + entity certs created in TPM");
        return loadCaFromTpm();
    }

  private:
    // Simics only: store the provisioned CA cert in the TPM CA slot
    // (ATTEST_TPM_CA_CERT_NV) and the trust-store slot
    // (ATTEST_TPM_TRUSTSTORE_CA_CERT_NV) so that mTLS connections succeed
    // without requiring a live certificate exchange.
    //
    // Both BMCs in Simics share the same firmware image and therefore the same
    // provisioned CA (/usr/share/attestation/ca.pem).  We exploit this to
    // skip the exchange step: the peer's CA is already known.
    //
    // Steps:
    //   0. Ensure /var/attestation/ca.* are present.
    //   1. Store the provisioned CA cert in ATTEST_TPM_CA_CERT_NV.
    //   2. Pre-populate the trust store (ATTEST_TPM_TRUSTSTORE_CA_CERT_NV and
    //      CA_PATH()) with the provisioned CA cert so connections are verified
    //      without a live exchange.
    static boost::system::error_code seedProvisionedCAIntoTPM(
        Tpm2CertManager& tpm)
    {
        // Step 0: seed /var/attestation/ca.* from the image defaults.
        if (!seedProvisionedCA())
        {
            LOG_ERROR(
                "Simics CA seed: failed to ensure provisioned CA files in /var");
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }

        // Step 1: store the provisioned CA cert in the TPM CA slot.
        auto ec = tpm.storeCertificateInTPMNV(PROVISIONED_CA_CERT_PATH,
                                              ATTEST_TPM_CA_CERT_NV);
        if (ec)
        {
            LOG_ERROR(
                "Simics CA seed: failed to store provisioned CA in TPM NV {}: {}",
                ATTEST_TPM_CA_CERT_NV, ec.message());
            return ec;
        }
        LOG_INFO("Simics CA seed: provisioned CA stored in TPM NV {}",
                 ATTEST_TPM_CA_CERT_NV);

        // Step 2: pre-populate the trust store with the provisioned CA cert.
        // Both Simics BMCs share the same provisioned CA, so we already know
        // the peer's CA — no live exchange needed for connections to succeed.
        // Inline the equivalent of CertificateExchanger::installCertificates
        // (which is declared later in this file and cannot be called here).
        auto caCert = loadCertificate(PROVISIONED_CA_CERT_PATH);
        if (!caCert)
        {
            LOG_ERROR(
                "Simics CA seed: failed to load provisioned CA cert for trust-store seeding");
            return boost::system::errc::make_error_code(
                boost::system::errc::no_such_file_or_directory);
        }
        // Write to the exchange CA path and create the hash symlink.
        createCertDirectories();
        if (!saveCertificate(CA_PATH(), caCert))
        {
            LOG_ERROR("Simics CA seed: failed to write CA to {}", CA_PATH());
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }
        if (!createCertificateHashFile(caCert, CA_PATH()))
        {
            LOG_ERROR("Simics CA seed: failed to create hash file for {}",
                      CA_PATH());
            return boost::system::errc::make_error_code(
                boost::system::errc::io_error);
        }
        // Store in TPM trust-store NV slot (0x01C10190).
        ec = tpm.storeCertificateInTPMNV(CA_PATH(),
                                         ATTEST_TPM_TRUSTSTORE_CA_CERT_NV);
        if (ec)
        {
            LOG_ERROR(
                "Simics CA seed: failed to store provisioned CA in TPM NV {}: {}",
                ATTEST_TPM_TRUSTSTORE_CA_CERT_NV, ec.message());
            return ec;
        }
        LOG_INFO("Simics CA seed: trust store pre-populated with provisioned CA"
                 " (no exchange needed)");

        return boost::system::error_code{};
    }

    // Returns true only when all three NV certs are readable AND the TPM
    // private keys still match their stored certificates.  A NV-only check
    // is insufficient: loadAndPersistTPMKey evicts and replaces the key at
    // a handle atomically, so after a partial failure the NV cert can
    // silently disagree with the key currently at the handle.
    static bool allCertsPresent(Tpm2CertManager& tpm)
    {
        // 1. Check every cert NV index is readable.
        X509Ptr probe(nullptr, &X509_free);
        if (reactor::Tpm2CertManager::readCertificateFromTPMNV(
                ATTEST_TPM_CA_CERT_NV, probe) ||
            reactor::Tpm2CertManager::readCertificateFromTPMNV(
                ATTEST_TPM_SERVER_CERT_NV, probe) ||
            reactor::Tpm2CertManager::readCertificateFromTPMNV(
                ATTEST_TPM_CLIENT_CERT_NV, probe))
        {
            LOG_DEBUG(
                "TPM: one or more cert NV indices missing, will recreate");
            return false;
        }

        // 2. Verify server key handle still matches its cert.
        //    Build a throw-away SSL_CTX, load cert + key, call
        //    SSL_CTX_check_private_key — this is the same check the TLS stack
        //    does at handshake time.
        X509Ptr serverCert(nullptr, &X509_free);
        if (reactor::Tpm2CertManager::readCertificateFromTPMNV(
                ATTEST_TPM_SERVER_CERT_NV, serverCert))
        {
            return false;
        }
        EVP_PKEYPtr serverKey(nullptr, &EVP_PKEY_free);
        std::string keyUri =
            std::format("handle:{}", ATTEST_TPM_SERVER_KEY_HANDLE);
        if (tpm.loadPrivateKeyFromTpm(keyUri, serverKey))
        {
            LOG_DEBUG("TPM: server key handle {} not accessible, will recreate",
                      ATTEST_TPM_SERVER_KEY_HANDLE);
            return false;
        }

        // Use a temporary SSL_CTX to check key/cert consistency.
        SSL_CTX* tmpCtx = SSL_CTX_new(TLS_server_method());
        if (!tmpCtx)
        {
            return false;
        }
        bool consistent =
            SSL_CTX_use_certificate(tmpCtx, serverCert.get()) == 1 &&
            SSL_CTX_use_PrivateKey(tmpCtx, serverKey.get()) == 1 &&
            SSL_CTX_check_private_key(tmpCtx) == 1;
        SSL_CTX_free(tmpCtx);

        if (!consistent)
        {
            LOG_WARNING(
                "TPM: server key/cert mismatch detected, will recreate all certs");
            // Suppress any OpenSSL errors from the failed check.
            ERR_clear_error();
        }
        return consistent;
    }

    // Reads the CA cert from TPM NV, promotes it to AUTHORITY_CA_CERT_PATH,
    // and returns it as an X509Ptr.
    static X509Ptr loadCaFromTpm()
    {
        X509Ptr caCert(nullptr, &X509_free);
        auto ec = reactor::Tpm2CertManager::readCertificateFromTPMNV(
            ATTEST_TPM_CA_CERT_NV, caCert);
        if (ec)
        {
            LOG_ERROR("TPM: failed to read CA cert from NV {}: {}",
                      ATTEST_TPM_CA_CERT_NV, ec.message());
            return makeX509Ptr(nullptr);
        }

        // Promote to filesystem path so the rest of the daemon can use it.
        namespace fs = std::filesystem;
        std::error_code fsEc;
        fs::create_directories(fs::path(AUTHORITY_CA_CERT_PATH).parent_path(),
                               fsEc);
        if (fsEc)
        {
            LOG_ERROR("TPM: failed to create authority directory: {}",
                      fsEc.message());
            return makeX509Ptr(nullptr);
        }

        FilePtr fp = makeFilePtr(fopen(AUTHORITY_CA_CERT_PATH, "w"));
        if (!fp || PEM_write_X509(fp.get(), caCert.get()) != 1)
        {
            LOG_ERROR("TPM: failed to write CA cert to {}",
                      AUTHORITY_CA_CERT_PATH);
            return makeX509Ptr(nullptr);
        }

        LOG_INFO("TPM CA cert promoted to {}", AUTHORITY_CA_CERT_PATH);
        return caCert;
    }
};

// ---------------------------------------------------------------------------
// Compile-time strategy selection: USE_TPM_CERTIFICATE selects the TPM
// strategy, otherwise the filesystem strategy is used.
// ---------------------------------------------------------------------------
#ifdef USE_TPM_CERTIFICATE
using DefaultCertStrategy = TpmCertStrategy;
#else
using DefaultCertStrategy = FileSystemCertStrategy;
#endif

inline std::unique_ptr<ICertificateStrategy> makeDefaultCertStrategy()
{
    return std::make_unique<DefaultCertStrategy>();
}

// ---------------------------------------------------------------------------
// CertificateExchanger
// ---------------------------------------------------------------------------

struct CertificateExchanger
{
    EventQueue& eventQueue;
    net::io_context& ioContext;
    X509Ptr mCaCert{nullptr, &X509_free};

    explicit CertificateExchanger(EventQueue& eventQueue,
                                  net::io_context& ioContext) :
        eventQueue(eventQueue), ioContext(ioContext)
    {
        // Load the CA cert that was already created at startup.
        // We never recreate keys here — doing so would invalidate the SSL
        // context that bmc-pairing-manager built from the same TPM handles.
        mCaCert = makeDefaultCertStrategy()->loadCa();
    }
    CertificateExchanger(const CertificateExchanger&) = delete;
    CertificateExchanger& operator=(const CertificateExchanger&) = delete;
    CertificateExchanger(CertificateExchanger&&) = delete;
    CertificateExchanger& operator=(CertificateExchanger&&) = delete;
    ~CertificateExchanger() = default;

    net::awaitable<bool> exchange(Streamer streamer)
    {
        createCertDirectories();
        LOG_DEBUG("Exchanging certificates");
        if (!co_await sendCertificate(streamer))
        {
            LOG_ERROR("Failed to send certificates");
            co_return false;
        }
        if (!co_await recieveCertificate(streamer))
        {
            LOG_ERROR("Failed to receive certificate");
            co_return false;
        }
        LOG_DEBUG("Certificate exchange completed successfully");
        co_return true;
    }
    net::awaitable<bool> waitForExchange(Streamer streamer)
    {
        createCertDirectories();
        if (!co_await recieveCertificate(streamer))
        {
            LOG_ERROR("Failed to receive certificate");
            co_return false;
        }
        if (!co_await sendCertificate(streamer))
        {
            LOG_ERROR("Failed to send certificate");
            co_return false;
        }
        co_return true;
    }

    static bool processInterMediateCA(
        const openssl_ptr<EVP_PKEY, EVP_PKEY_free>& pkey,
        const openssl_ptr<X509, X509_free>& ca, const std::string& hostName)
    {
        return processInterMediateCACerts(pkey, ca, hostName);
    }
    static bool installCertificates(const std::string& castr)
    {
        return makeDefaultCertStrategy()->install(castr);
    }
    net::awaitable<bool> sendCertificate(Streamer streamer)
    {
        if (!mCaCert)
        {
            co_return false;
        }
        std::string intermediate_ca =
            toString(mCaCert); // Convert to string for sending

        nlohmann::json jsonBody;
        jsonBody["CA"] = intermediate_ca;
        auto [ec, size] = co_await sendHeader(
            streamer, makeEvent(INSTALL_CERTIFICATES, jsonBody.dump()));
        if (ec)
        {
            LOG_ERROR("Failed to send INSTALL_CERTIFICATES event: {}",
                      ec.message());
            co_return false;
        }
        if (!co_await recieveCertificateStatus(streamer))
        {
            LOG_ERROR("Failed to Install certificates");
            co_return false;
        }
        LOG_DEBUG("Certificates installed successfully");
        co_return true;
    }
    static net::awaitable<bool> recieveCertificateStatus(Streamer streamer)
    {
        auto [ec, event] = co_await readHeader(streamer);
        if (ec)
        {
            LOG_ERROR("Failed to read response: {}", ec.message());
            co_return false;
        }
        auto [id, body] = parseEvent(event);
        if (id == INSTALL_CERTIFICATES_RESP)
        {
            auto jsonBody = nlohmann::json::parse(body);
            auto installed = jsonBody["status"].get<bool>();
            if (!installed)
            {
                LOG_ERROR("Failed to install certificates");
                co_return false;
            }
            LOG_DEBUG("Certificates installed successfully");
            co_return true;
        }

        LOG_ERROR("Unexpected event ID: {}", id);
        co_return false;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-reference-coroutine-parameters)
    static net::awaitable<bool> sendInstallStatus(Streamer& streamer,
                                                  bool status)
    {
        nlohmann::json jsonBody;
        jsonBody["status"] = status;
        auto [ec, size] = co_await sendHeader(
            streamer, makeEvent(INSTALL_CERTIFICATES_RESP, jsonBody.dump()));
        if (ec)
        {
            LOG_ERROR("Failed to send INSTALL_CERTIFICATES_RESP event: {}",
                      ec.message());
            co_return false;
        }
        co_return status;
    }
    static net::awaitable<bool> recieveCertificate(Streamer streamer)
    {
        auto [ec, event] = co_await readHeader(streamer);
        if (ec)
        {
            LOG_ERROR("Failed to read response: {}", ec.message());
            co_return false;
        }
        auto [id, body] = parseEvent(event);
        if (id == INSTALL_CERTIFICATES)
        {
            auto jsonBody = nlohmann::json::parse(body);
            auto CA = jsonBody["CA"].get<std::string>();
            if (CA.empty())
            {
                LOG_ERROR("CA or PKEY is empty in the event body");
                co_return co_await sendInstallStatus(streamer, false);
            }
            if (!installCertificates(CA))
            {
                LOG_ERROR("Failed to install certificates");
                co_return co_await sendInstallStatus(streamer, false);
            }
            co_return co_await sendInstallStatus(streamer, true);
        }
        LOG_ERROR("Unexpected event ID: {}", id);
        co_return false;
    }
};
