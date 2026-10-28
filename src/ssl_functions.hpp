#pragma once
#include "beastdefs.hpp"
#include "logger.hpp"
#include "tpm2_cert_manager.hpp"
#include "tpm_handles.hpp"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <filesystem>
#include <format>
#include <optional>
#include <string>
using namespace reactor;
namespace fs = std::filesystem;

inline std::string trustStorePath()
{
    return "/etc/ssl/certs/authority";
}
inline std::string ENTITY_CLIENT_CERT_PATH()
{
    return "/etc/ssl/certs/https/client_cert.pem";
}
inline std::string CLIENT_PKEY_PATH()
{
    return "/etc/ssl/private/client_pkey.pem";
}
inline std::string ENTITY_SERVER_CERT_PATH()
{
    return "/etc/ssl/certs/https/server_cert.pem";
}
inline std::string SERVER_PKEY_PATH()
{
    return "/etc/ssl/private/server_pkey.pem";
}
inline bool sslVerifyCallback(bool preverified,
                              boost::asio::ssl::verify_context& ctx)
{
    X509_STORE_CTX* store_ctx = ctx.native_handle();
    int err = X509_STORE_CTX_get_error(store_ctx);
    int depth = X509_STORE_CTX_get_error_depth(store_ctx);

    X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
    std::array<char, 256> subject{};
    if (cert != nullptr)
    {
        X509_NAME_oneline(X509_get_subject_name(cert), subject.data(),
                          static_cast<int>(subject.size()));
    }

    if (!preverified)
    {
        LOG_ERROR(
            "SSL certificate verification failed: depth={}, error={} ({}), subject={}",
            depth, err, X509_verify_cert_error_string(err), subject.data());
    }
    else
    {
        LOG_DEBUG("SSL certificate verification ok: depth={}, subject={}",
                  depth, subject.data());
    }
    return preverified;
}

std::optional<ssl::context> getClientContext()
{
    if (fs::exists(ENTITY_CLIENT_CERT_PATH()) &&
        fs::exists(CLIENT_PKEY_PATH()) && fs::exists(trustStorePath()))
    {
        boost::asio::ssl::context ssl_context(
            boost::asio::ssl::context::tls_client);

        // Configure the context for modern, secure operation
        ssl_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1);

        // Set the ciphers to only use secure, modern ones
        // This should be compatible with the server's cipher list
        SSL_CTX_set_cipher_list(
            ssl_context.native_handle(),
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        ssl_context.add_verify_path(trustStorePath());
        ssl_context.set_verify_mode(boost::asio::ssl::verify_peer);
        ssl_context.set_verify_callback(sslVerifyCallback);
        ssl_context.use_certificate_chain_file(ENTITY_CLIENT_CERT_PATH());
        ssl_context.use_private_key_file(CLIENT_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        return {std::move(ssl_context)};
    }
    LOG_ERROR("Client SSL context files are missing searched paths: {}, {}, {}",
              ENTITY_CLIENT_CERT_PATH(), CLIENT_PKEY_PATH(), trustStorePath());
    return std::nullopt;
}
std::optional<ssl::context> getServerContext()
{
    if (fs::exists(ENTITY_SERVER_CERT_PATH()) &&
        fs::exists(SERVER_PKEY_PATH()) && fs::exists(trustStorePath()))
    {
        // Create a context that supports TLS 1.2 and 1.3
        boost::asio::ssl::context ssl_context(
            boost::asio::ssl::context::tls_server);

        // Configure the context for modern, secure operation
        ssl_context.set_options(
            boost::asio::ssl::context::default_workarounds |
            boost::asio::ssl::context::no_sslv2 |
            boost::asio::ssl::context::no_sslv3 |
            boost::asio::ssl::context::no_tlsv1 |
            boost::asio::ssl::context::no_tlsv1_1 |
            boost::asio::ssl::context::single_dh_use);

        // Set the ciphers to only use secure, modern ones
        // This is an example, you can get a list of modern ciphers from tools
        // like Mozilla SSL Config Generator
        SSL_CTX_set_cipher_list(
            ssl_context.native_handle(),
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        ssl_context.use_certificate_chain_file(ENTITY_SERVER_CERT_PATH());
        ssl_context.use_private_key_file(SERVER_PKEY_PATH(),
                                         boost::asio::ssl::context::pem);
        ssl_context.add_verify_path(trustStorePath());
        ssl_context.set_verify_mode(
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_fail_if_no_peer_cert);
        ssl_context.set_verify_callback(sslVerifyCallback);
        return {std::move(ssl_context)};
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// TPM-backed SSL context builders
// ---------------------------------------------------------------------------

inline std::optional<ssl::context> getTpmClientContext()
{
    auto& tpm = NSNAME::Tpm2CertManager::getInstance();
    if (!tpm.isInitialized())
    {
        LOG_DEBUG("TPM2 provider not initialized, skipping TPM client context");
        return std::nullopt;
    }

    auto [ec, ctx] = tpm.createMTLSClientContext(
        TPM_CLIENT_KEY_HANDLE, TPM_CLIENT_CERT_NV, TPM_CLIENT_CA_CERT_NV,
        TPM_TRUSTSTORE_CA_CERT_NV);
    if (ec)
    {
        LOG_WARNING("Failed to build TPM client SSL context: {}", ec.message());
        return std::nullopt;
    }

    SSL_CTX_set_cipher_list(
        ctx.native_handle(),
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    if (!NSNAME::Tpm2CertManager::isEccSupported())
    {
        ctx.set_options(boost::asio::ssl::context::no_tlsv1_3);
        SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_2_VERSION);
        SSL_CTX_set1_sigalgs_list(ctx.native_handle(),
                                  "RSA+SHA256:RSA+SHA384:RSA+SHA512");
    }
    ctx.set_verify_callback(sslVerifyCallback);
    LOG_INFO("TPM client SSL context created successfully");
    return {std::move(ctx)};
}

inline std::optional<ssl::context> getTpmServerContext()
{
    auto& tpm = NSNAME::Tpm2CertManager::getInstance();
    if (!tpm.isInitialized())
    {
        LOG_DEBUG("TPM2 provider not initialized, skipping TPM server context");
        return std::nullopt;
    }

    auto [ec, ctx] = tpm.createMTLSServerContext(
        TPM_SERVER_KEY_HANDLE, TPM_SERVER_CERT_NV, TPM_SERVER_CA_CERT_NV,
        TPM_TRUSTSTORE_CA_CERT_NV);
    if (ec)
    {
        LOG_WARNING("Failed to build TPM server SSL context: {}", ec.message());
        return std::nullopt;
    }

    SSL_CTX_set_cipher_list(
        ctx.native_handle(),
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    if (!NSNAME::Tpm2CertManager::isEccSupported())
    {
        ctx.set_options(boost::asio::ssl::context::no_tlsv1_3);
        SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_2_VERSION);
        SSL_CTX_set1_sigalgs_list(ctx.native_handle(),
                                  "RSA+SHA256:RSA+SHA384:RSA+SHA512");
        SSL_CTX_set1_client_sigalgs_list(ctx.native_handle(),
                                         "RSA+SHA256:RSA+SHA384:RSA+SHA512");
    }
    ctx.set_verify_callback(sslVerifyCallback);
    LOG_INFO("TPM server SSL context created successfully");
    return {std::move(ctx)};
}

// ---------------------------------------------------------------------------
// Helpers: compile-time selection. USE_TPM_CERTIFICATE selects TPM-backed
// contexts, otherwise filesystem PEM files are used.
// ---------------------------------------------------------------------------

inline std::optional<ssl::context> getClientContextWithFallback()
{
#ifdef USE_TPM_CERTIFICATE
    return getTpmClientContext();
#else
    return getClientContext();
#endif
}

inline std::optional<ssl::context> getServerContextWithFallback()
{
#ifdef USE_TPM_CERTIFICATE
    return getTpmServerContext();
#else
    return getServerContext();
#endif
}
