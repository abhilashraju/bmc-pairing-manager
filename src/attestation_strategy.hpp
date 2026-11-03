#pragma once
#include "beastdefs.hpp"
#include "dbusproperty_watcher.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"
#include "spdm_attestation.hpp"

#include <chrono>
#include <format>
#include <memory>
#include <optional>
#include <string>

namespace NSNAME
{
/**
 * Attestation strategies.
 *
 * An attestation strategy performs the requester side of the attestation
 * handshake with the peer identified by @c deviceName and reports whether the
 * peer was successfully attested.
 *
 * Required interface:
 * @code
 * // Requester side: attest the peer, true on success.
 * static net::awaitable<bool> attest(
 *     std::shared_ptr<sdbusplus::asio::connection> conn,
 *     std::string deviceName);
 *
 * // Responder side: invoke @c handler whenever the peer's attestation
 * // state changes. The handler is called as
 * // net::awaitable<void>(boost::system::error_code, std::optional<bool>).
 * static void watchAttestationState(
 *     net::io_context& ioc,
 *     const std::shared_ptr<sdbusplus::asio::connection>& conn,
 *     WatchHandler<bool> auto handler);
 * @endcode
 *
 * The strategy is selected at compile time. Define USE_SPDM_ATTESTATION to
 * use SpdmAttestationStrategy, otherwise AttestationStubStrategy is used.
 */

/**
 * Strategy backed by the attestation stub service
 * (xyz.openbmc_project.attestation). It triggers "attest" on the device object
 * and waits for the "Attested" signal.
 */
struct AttestationStubStrategy
{
    static constexpr auto svc = "xyz.openbmc_project.attestation";
    static constexpr auto devicePath =
        "/xyz/openbmc_project/attestation_requester/devices/tcp/{}";
    static constexpr auto deviceIntf = "xyz.openbmc_project.AttestationDevice";
    static constexpr auto attestedSignal = "Attested";
    static constexpr auto responderIntf =
        "xyz.openbmc_project.AttestationResponder";
    static constexpr auto responderSignal = "Attested";
    static constexpr auto attestTimeout = std::chrono::seconds(30);

    static void watchAttestationState(
        net::io_context& ioc,
        const std::shared_ptr<sdbusplus::asio::connection>& conn,
        WatchHandler<bool> auto handler)
    {
        DbusSignalWatcher<bool>::watch(ioc, conn, std::move(handler),
                                       responderIntf, responderSignal);
    }

    static net::awaitable<bool> attest(
        std::shared_ptr<sdbusplus::asio::connection> conn,
        std::string deviceName)
    {
        LOG_INFO("Starting attestation using attestation stub");
        auto device = std::format(devicePath, deviceName);
        auto [ec, msg] =
            co_await awaitable_dbus_method_call<sdbusplus::message_t>(
                *conn, svc, device, deviceIntf, "attest");

        if (ec)
        {
            LOG_ERROR("Failed to start attestation: {}", ec.message());
            co_return false;
        }

        auto watcher =
            DbusSignalWatcher<bool>::create(conn, deviceIntf, attestedSignal);
        std::optional<bool> val = co_await watcher->watchOnce(attestTimeout);
        co_return val && *val;
    }
};

#ifdef USE_SPDM_ATTESTATION
using AttestationStrategy = SpdmAttestationStrategy;
#else
using AttestationStrategy = AttestationStubStrategy;
#endif
} // namespace NSNAME
