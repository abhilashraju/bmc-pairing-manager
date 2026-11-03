#pragma once
#include "beastdefs.hpp"
#include "dbusproperty_watcher.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"

#include <memory>
#include <string>

namespace NSNAME
{
/**
 * Strategy that performs attestation by calling SPDM directly.
 * Not implemented yet.
 */
struct SpdmAttestationStrategy
{
    static net::awaitable<bool> attest(
        [[maybe_unused]] std::shared_ptr<sdbusplus::asio::connection> conn,
        [[maybe_unused]] std::string deviceName)
    {
        LOG_ERROR("SPDM attestation strategy is not implemented");
        co_return false;
    }

    static void watchAttestationState(
        [[maybe_unused]] net::io_context& ioc,
        [[maybe_unused]] const std::shared_ptr<sdbusplus::asio::connection>&
            conn,
        [[maybe_unused]] WatchHandler<bool> auto handler)
    {
        LOG_ERROR("SPDM attestation state watcher is not implemented");
    }
};
} // namespace NSNAME
