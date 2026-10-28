#pragma once
#include "cert_generator.hpp"
#include "logger.hpp"

#include <unistd.h>

#include <filesystem>
#include <iomanip>
#include <sstream>

// Default CA cert and key shipped read-only in the firmware image.
// Used as the source on first boot or after a factory reset (/var wipe).
constexpr auto DEFAULT_CA_CERT_PATH = "/usr/share/attestation/ca.pem";
constexpr auto DEFAULT_CA_KEY_PATH = "/usr/share/attestation/ca.key";

// Persistent working copy in /var — survives firmware reflash.
// Populated from DEFAULT_CA_*_PATH on first boot if absent.
constexpr auto PROVISIONED_CA_CERT_PATH = "/var/attestation/ca.pem";
constexpr auto PROVISIONED_CA_KEY_PATH = "/var/attestation/ca.key";

// Runtime SSL paths — populated by FileSystemCertStrategy on every boot.
constexpr auto AUTHORITY_CA_CERT_PATH = "/etc/ssl/certs/authority/ca.pem";
constexpr auto AUTHORITY_CA_KEY_PATH = "/etc/ssl/private/ca.key";

constexpr auto CA_PATH_X = "{}etc/ssl/certs/authority/ca.pem";
constexpr auto SELF_CA_PATH_X = "{}etc/ssl/certs/self_ca.pem";
constexpr auto SERVER_PKEY_PATH_X = "{}etc/ssl/private/server_pkey.pem";
constexpr auto ENTITY_SERVER_CERT_PATH_X =
    "{}etc/ssl/certs/https/server_cert.pem";
constexpr auto CLIENT_PKEY_PATH_X = "{}etc/ssl/private/client_pkey.pem";
constexpr auto ENTITY_CLIENT_CERT_PATH_X =
    "{}etc/ssl/certs/https/client_cert.pem";
constexpr auto ENTITY_SERVER_COMBINED_PATH_X =
    "{}etc/ssl/certs/https/server.pem";
constexpr auto ENTITY_CLIENT_COMBINED_PATH_X =
    "{}etc/ssl/certs/https/client.pem";
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern std::string prefix;
inline std::string getPrefix()
{
    return prefix.empty() ? std::format("/tmp/{}/", ::getpid()) : prefix;
}
inline std::string SELF_CA_PATH()
{
    return std::format(SELF_CA_PATH_X, getPrefix());
}
inline std::string CA_PATH()
{
    return std::format(CA_PATH_X, getPrefix());
}
inline std::string SERVER_PKEY_PATH()
{
    return std::format(SERVER_PKEY_PATH_X, getPrefix());
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return std::format(ENTITY_SERVER_CERT_PATH_X, getPrefix());
}
inline std::string CLIENT_PKEY_PATH()
{
    return std::format(CLIENT_PKEY_PATH_X, getPrefix());
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return std::format(ENTITY_CLIENT_CERT_PATH_X, getPrefix());
}
inline std::string ENTITY_SERVER_COMBINED_PATH()
{
    return std::format(ENTITY_SERVER_COMBINED_PATH_X, getPrefix());
}
inline std::string ENTITY_CLIENT_COMBINED_PATH()
{
    return std::format(ENTITY_CLIENT_COMBINED_PATH_X, getPrefix());
}

// Helper: copy src to dst with given permissions, creating parent dirs.
inline bool copyFile(const std::string& src, const std::string& dst,
                     std::filesystem::perms perms)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::create_directories(fs::path(dst).parent_path(), ec);
    if (ec)
    {
        LOG_ERROR("Failed to create directory for {}: {}", dst, ec.message());
        return false;
    }
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    if (ec)
    {
        LOG_ERROR("Failed to copy {} to {}: {}", src, dst, ec.message());
        return false;
    }
    fs::permissions(dst, perms, ec);
    return true;
}

// Returns true when running under Simics simulation.
// TEMPORARY: the /host check is disabled and this always returns false,
// because /host also exists on real BMC images and caused them to take the
// Simics certificate path.
inline bool isSimics()
{
    // return std::filesystem::exists("/host");
    return true;
}

// Always seed /var/attestation/ca.* from /usr/share/attestation/ (default
// shipped in the firmware image), overwriting any previous copy so every BMC
// running the same image uses the same CA.  Shared by all cert strategies;
// each strategy does its own further seeding on top of this.
inline bool seedProvisionedCA()
{
    namespace fs = std::filesystem;

    if (!fs::exists(DEFAULT_CA_CERT_PATH))
    {
        LOG_ERROR("Default CA certificate not found at {}",
                  DEFAULT_CA_CERT_PATH);
        return false;
    }
    if (!fs::exists(DEFAULT_CA_KEY_PATH))
    {
        LOG_ERROR("Default CA private key not found at {}",
                  DEFAULT_CA_KEY_PATH);
        return false;
    }

    if (!copyFile(DEFAULT_CA_CERT_PATH, PROVISIONED_CA_CERT_PATH,
                  fs::perms::owner_read | fs::perms::owner_write |
                      fs::perms::group_read | fs::perms::others_read))
    {
        return false;
    }
    if (!copyFile(DEFAULT_CA_KEY_PATH, PROVISIONED_CA_KEY_PATH,
                  fs::perms::owner_read | fs::perms::owner_write))
    {
        return false;
    }
    LOG_INFO("CA seeded into /var/attestation from image defaults");
    return true;
}

inline void createCertDirectories()
{
    if (std::filesystem::exists(
            std::filesystem::path(CA_PATH()).parent_path()) &&
        std::filesystem::exists(
            std::filesystem::path(SERVER_PKEY_PATH()).parent_path()) &&
        std::filesystem::exists(
            std::filesystem::path(ENTITY_SERVER_CERT_PATH()).parent_path()))
    {
        LOG_DEBUG("Directories already exist, skipping creation");
        return;
    }
    LOG_DEBUG("Creating directories for certificates at {}, {}, {}", CA_PATH(),
              SERVER_PKEY_PATH(), ENTITY_SERVER_CERT_PATH());
    std::filesystem::create_directories(
        std::filesystem::path(CA_PATH()).parent_path());
    std::filesystem::create_directories(
        std::filesystem::path(SERVER_PKEY_PATH()).parent_path());
    std::filesystem::create_directories(
        std::filesystem::path(ENTITY_SERVER_CERT_PATH()).parent_path());
}
inline void clearCertificates()
{
    if (std::filesystem::exists(std::filesystem::path(CA_PATH())))
    {
        std::filesystem::remove(std::filesystem::path(CA_PATH()));
    }
    if (std::filesystem::exists(std::filesystem::path(SERVER_PKEY_PATH())))
    {
        std::filesystem::remove(std::filesystem::path(SERVER_PKEY_PATH()));
    }
    if (std::filesystem::exists(
            std::filesystem::path(ENTITY_SERVER_CERT_PATH())))
    {
        std::filesystem::remove(
            std::filesystem::path(ENTITY_SERVER_CERT_PATH()));
    }
    if (std::filesystem::exists(std::filesystem::path(CLIENT_PKEY_PATH())))
    {
        std::filesystem::remove(std::filesystem::path(CLIENT_PKEY_PATH()));
    }
    if (std::filesystem::exists(
            std::filesystem::path(ENTITY_CLIENT_CERT_PATH())))
    {
        std::filesystem::remove(
            std::filesystem::path(ENTITY_CLIENT_CERT_PATH()));
    }
}
