#include "bmc_pairing_manager_object.hpp"
#include "bmcresponder.hpp"
#include "cert_generator.hpp"
#include "command_line_parser.hpp"
#include "dbusproperty_watcher.hpp"
#include "debug_controller.hpp"
#include "lldp_neighbour_handlers.hpp"
#include "ssl_functions.hpp"
#include "tcp_client.hpp"
#include "tcp_server.hpp"

#include <unistd.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/bus/match.hpp>

#include <fstream>
#include <iostream>
static constexpr auto ATTESTATION_SVC = "xyz.openbmc_project.attestation";
static constexpr auto ATTESTATION_DEVICE_PATH =
    "/xyz/openbmc_project/attestation_requester/devices/tcp/{}";
static constexpr auto ATTESTATION_RES_PATH =
    "/xyz/openbmc_project/attestation_responder/tcp/{}";
static constexpr auto ATTESTATION_DEVICE_INTF =
    "xyz.openbmc_project.AttestationDevice";
static constexpr auto ATTESTATION_RES_INTF =
    "xyz.openbmc_project.AttestationResponder";
static constexpr auto ATTESTATION_PROP = "Status";
static constexpr auto ATTESTATION_REQ_SIGNAL = "Attested";
static constexpr auto ATTESTATION_RES_SIGNAL = "Attested";
static constexpr auto LLDP_PROP = "ManagementAddressIPv4";
using DbusObjectPath = std::string;
using DbusInterface = std::string;
using PropertyValue = std::string;
using DbusService = std::string;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int gRetryTime = 30;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static int gRetryCount = 3;
net::awaitable<void> waitFor(boost::asio::any_io_executor ctx,
                             std::chrono::seconds duration)
{
    net::steady_timer timer(ctx, duration);
    co_await timer.async_wait(net::use_awaitable);
}
net::awaitable<std::optional<std::string>> getRemoteIp(
    std::reference_wrapper<sdbusplus::asio::connection> conn, std::string iface)
{
    auto [ec, propVal] = co_await getProperty<std::string>(
        conn.get(), LLDP_SVC, std::format(LLDP_REC_PATH, iface), LLDP_INTF,
        LLDP_PROP);
    if (ec)
    {
        LOG_ERROR("Failed to get LLDP property: {}", ec.message());
        co_return std::nullopt;
    }
    co_return std::optional(propVal);
}
net::awaitable<bool> writeHello(std::reference_wrapper<TcpClient> client)
{
    std::string message("Hello");
    int retryCount = 3;

    while (retryCount > 0)
    {
        auto [ec, bytes] = co_await client.get().write(net::buffer(message));

        if (!ec)
        {
            co_return true; // Success
        }

        if (ec == net::error::operation_aborted)
        {
            retryCount--;
            LOG_INFO(
                "Write operation timed out, retrying... ({} attempts left)",
                retryCount);
            continue;
        }
        LOG_ERROR("Connect error: {}", ec.message());
        co_return false;
    }
    co_return false;
}
net::awaitable<bool> writePing(std::reference_wrapper<TcpClient> client)
{
    std::string ping("ping");
    auto [ec, bytes] = co_await client.get().write(net::buffer(ping));

    if (!ec)
    {
        co_return true; // Success
    }

    if (ec == net::error::operation_aborted)
    {
        LOG_INFO("Ping write operation timed out, continuing...");
        co_return true; // Return true to continue the loop
    }

    LOG_ERROR("Send error: {}", ec.message());
    co_return false; // Return false to exit the loop on other errors
}
net::awaitable<std::pair<std::optional<std::string>, bool>> read(
    std::reference_wrapper<TcpClient> client,
    std::reference_wrapper<std::array<char, 1024>> buffer)
{
    auto [ec, bytes] = co_await client.get().read(net::buffer(buffer.get()));

    if (!ec)
    {
        co_return std::make_pair(std::string(buffer.get().data(), bytes), true);
    }

    if (ec == net::error::operation_aborted)
    {
        // LOG_INFO("Read operation timed out, continuing...");
        co_return std::make_pair(std::nullopt, true); // Continue on timeout
    }

    LOG_ERROR("Receive error: {}", ec.message());
    co_return std::make_pair(std::nullopt, false); // Exit on other errors
}
net::awaitable<bool> monitorBmc(
    std::reference_wrapper<net::io_context> io_context,
    std::reference_wrapper<TcpClient> client, bool needping = false)
{
    if (!co_await writeHello(client))
    {
        co_return false;
    }
    std::array<char, 1024> data{0};
    while (true)
    {
        auto [message, shouldContinue] = co_await read(client, std::ref(data));
        if (!shouldContinue)
        {
            co_return false; // Exit on error
        }
        if (!message)
        {
            continue; // Timeout, continue reading
        }
        LOG_DEBUG("Received from BMC: {}", *message);
        if (needping)
        {
            if (!co_await writePing(client))
            {
                co_return false; // Exit on error (not timeout)
            }
            co_await waitFor(io_context.get().get_executor(), 5s);
        }
    }
    co_return false;
}
net::awaitable<boost::system::error_code> connect(
    std::reference_wrapper<TcpClient> client, std::string ip, short port)
{
    int retryCount = gRetryCount;
    while (retryCount--)
    {
        auto ec = co_await client.get().connect(ip, std::to_string(port));

        if (ec)
        {
            if (ec.category() ==
                boost::asio::error::ssl_category) // check SSL error
            {
                LOG_ERROR("SSL connect error: {} {}", ip, ec.message());
                co_return ec;
            }

            if (retryCount <= 0)
            {
                LOG_ERROR("Connect error: {} {}", ip, ec.message());
                co_return ec;
            }

            // retry after delay
            auto executor = co_await boost::asio::this_coro::executor;
            co_await waitFor(executor, std::chrono::seconds(gRetryTime));
            continue;
        }
        break;
    }
    co_return boost::system::error_code{};
}
net::awaitable<void> tryConnect(
    std::reference_wrapper<net::io_context> io_context, std::string /*ip*/,
    short port, std::reference_wrapper<BmcPairingManagerObject> controller)
{
    auto dir = BmcPairingManagerObject::ConnectionDirection::outgoing;
    controller.get().setPeerConnected(
        BmcPairingIface::PeerConnectionStatus::InProgress, dir);
    LOG_DEBUG("Trying peer connection");
    auto sslCtx = getClientContextWithFallback();

    if (!sslCtx)
    {
        LOG_ERROR("ssl context is not available");
        controller.get().setPeerConnected(
            BmcPairingIface::PeerConnectionStatus::NotConnected, dir);
        co_return;
    }
    TcpClient client(io_context.get().get_executor(), *sslCtx);
    auto ec = co_await connect(std::ref(client), "bmc.peer", port);

    if (ec)
    {
        controller.get().setPeerConnected(
            BmcPairingIface::PeerConnectionStatus::NotConnected, dir);
        co_return;
    }
    controller.get().setPeerConnected(
        BmcPairingIface::PeerConnectionStatus::Connected, dir);
    co_await monitorBmc(io_context, std::ref(client));
    controller.get().setPeerConnected(
        BmcPairingIface::PeerConnectionStatus::NotConnected, dir);
}

std::shared_ptr<BmcResponder> makeBmcResponder(
    net::io_context& ctx, ssl::context sslCtx, short port,
    BmcPairingManagerObject& controller)
{
    auto bmcResponder =
        std::make_shared<BmcResponder>(ctx, std::move(sslCtx), port);

    bmcResponder->onConnectionChange([&controller](bool connected) {
        controller.setPeerConnected(
            connected ? BmcPairingIface::PeerConnectionStatus::Connected
                      : BmcPairingIface::PeerConnectionStatus::NotConnected,
            BmcPairingManagerObject::ConnectionDirection::incoming);
    });
    return bmcResponder;
}
net::awaitable<void> onNeighbourFound(
    std::reference_wrapper<net::io_context> io_context,
    std::reference_wrapper<BmcPairingManagerObject> controller, short rport,
    std::string address, std::string name)
{
    LOG_INFO("LLDP Neighbour IP found: {} Name: {}", address, name);
    if (controller.get().peerConnected(
            BmcPairingManagerObject::ConnectionDirection::outgoing) ==
        BmcPairingIface::PeerConnectionStatus::Connected)
    {
        LOG_INFO("Peer already connected, skipping connection attempt");
        co_return;
    }
    co_await waitFor(io_context.get().get_executor(), 15s);
    co_await tryConnect(io_context, address, rport, controller);
    co_return;
}
net::awaitable<void> onSpdmStateChange(
    std::reference_wrapper<net::io_context> io_context, short port,
    std::reference_wrapper<BmcPairingManagerObject> controller,
    std::reference_wrapper<std::shared_ptr<BmcResponder>> bmcResponder,
    boost::system::error_code ec, std::optional<bool> val)
{
    if (ec || !val)
    {
        co_return;
    }
    co_await controller.get().setPaired(*val);
    if (*val)
    {
        LOG_INFO("SPDM pairing completed successfully");

        // Reset existing responder to close any active connections gracefully
        if (bmcResponder.get())
        {
            LOG_INFO("Closing existing BMC responder before recreating");
            bmcResponder.get().reset();
        }

        auto sslContext = getServerContextWithFallback();
        if (!sslContext)
        {
            LOG_ERROR("ssl context is not available");
            co_return;
        }
        bmcResponder.get() = makeBmcResponder(
            io_context.get(), std::move(*sslContext), port, controller.get());
        co_return;
    }
    LOG_INFO("SPDM pairing completed with failed status");
}

net::awaitable<void> startSpdm(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::reference_wrapper<net::io_context> ioc, short port, std::string iface,
    std::reference_wrapper<BmcPairingManagerObject> controller,
    std::reference_wrapper<std::shared_ptr<BmcResponder>> bmcResponder,
    std::string deviceName)
{
    try
    {
        // This method would start the SPDM provisioning process.
        // Implementation would depend on the specific requirements.
        LOG_INFO("Starting SPDM pairing");
        auto device = std::format(ATTESTATION_DEVICE_PATH, deviceName);
        auto [ec, msg] =
            co_await awaitable_dbus_method_call<sdbusplus::message_t>(
                *conn, ATTESTATION_SVC, device, ATTESTATION_DEVICE_INTF,
                "attest");

        if (ec)
        {
            LOG_ERROR("Failed to start spdm: {}", ec.message());
            co_return;
        }

        auto watcher = DbusSignalWatcher<bool>::create(
            conn, ATTESTATION_DEVICE_INTF, ATTESTATION_REQ_SIGNAL);
        std::optional<bool> val = co_await watcher->watchOnce(30s);

        if (val && *val)
        {
            LOG_INFO("SPDM pairing completed successfully (requester)");
            co_await controller.get().setPaired(true);

            // Rebuild the server context now that the peer CA is available
            // in TPM NV (written by installCertificates during cert exchange).
            if (bmcResponder.get())
            {
                LOG_INFO("Closing existing BMC responder before recreating");
                bmcResponder.get().reset();
            }
            auto sslContext = getServerContextWithFallback();
            if (!sslContext)
            {
                LOG_ERROR("ssl context is not available after SPDM pairing");
            }
            else
            {
                bmcResponder.get() = makeBmcResponder(
                    ioc.get(), std::move(*sslContext), port, controller.get());
            }

            auto ip = co_await getRemoteIp(*conn, iface);
            if (ip)
            {
                net::co_spawn(ioc.get(),
                              std::bind_front(tryConnect, std::ref(ioc), *ip,
                                              port, std::ref(controller)),
                              net::detached);
                co_return;
            }
        }
        LOG_ERROR("SPDM pairing failed or timed out");
    }
    catch (std::exception& e)
    {
        LOG_ERROR("SPDM pairing failed {}", e.what());
    }
}
nlohmann::json loadConfig(const std::string& configPath)
{
    std::ifstream confFile(configPath);
    nlohmann::json config;

    if (confFile)
    {
        try
        {
            config = nlohmann::json::parse(confFile);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            LOG_ERROR("JSON parse error in config file: {}", e.what());
            throw std::runtime_error("Invalid JSON configuration file");
        }
    }
    else
    {
        config = nlohmann::json{{"port", 8090}, {"interface_id", "eth2"}};
    }

    // Validate port number (1-65535)
    if (config.contains("port"))
    {
        int port = config["port"];
        if (port < 1 || port > 65535)
        {
            LOG_ERROR("Invalid port number: {}. Must be between 1-65535", port);
            throw std::runtime_error("Invalid port number in configuration");
        }
    }

    return config;
}

struct ApplicationConfig
{
    short port;
    std::string interface_id;
    int retry_count;
    int retry_timer;
};

ApplicationConfig loadAndValidateConfig(const std::string& configPath)
{
    auto confJson = loadConfig(configPath);
    ApplicationConfig config{
        .port = static_cast<short>(confJson.value("port", 8090)),
        .interface_id = confJson.value("interface_id", std::string{"eth2"}),
        .retry_count = confJson.value("retry_count", 3),
        .retry_timer = confJson.value("retry_timer", 30)};

    gRetryCount = config.retry_count;
    gRetryTime = config.retry_timer;

    return config;
}

std::shared_ptr<BmcResponder> initializeResponder(
    net::io_context& io_context, short port,
    BmcPairingManagerObject& controller)
{
    auto sslCtx = getServerContextWithFallback();
    if (!sslCtx)
    {
        LOG_WARNING("SSL context unavailable, responder not initialized");
        return nullptr;
    }

    return makeBmcResponder(io_context, std::move(*sslCtx), port, controller);
}

std::function<void(const std::string&)> createPairingHandler(
    net::io_context& io_context,
    const std::shared_ptr<sdbusplus::asio::connection>& conn, short port,
    const std::string& iface, BmcPairingManagerObject& controller,
    std::shared_ptr<BmcResponder>& bmcResponder)
{
    return [&io_context, conn, port, iface, &controller,
            &bmcResponder](const std::string& deviceName) {
        LOG_INFO("Pairing started");
        net::co_spawn(io_context,
                      std::bind_front(startSpdm, conn, std::ref(io_context),
                                      port, iface, std::ref(controller),
                                      std::ref(bmcResponder), deviceName),
                      net::detached);
    };
}

auto createNeighbourHandler(net::io_context& io_context,
                            BmcPairingManagerObject& controller, short port)
{
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    return [&io_context, &controller, port](
               std::string address, std::string name) -> net::awaitable<void> {
        co_await onNeighbourFound(std::ref(io_context), std::ref(controller),
                                  port, address, name);
    };
}

auto createFallbackHandler(
    net::io_context& io_context,
    const std::shared_ptr<sdbusplus::asio::connection>& conn,
    const std::string& iface, auto neighbourHandler)
{
    return [&io_context, conn, &iface, neighbourHandler]() {
        net::co_spawn(io_context,
                      makeNeighbourUpdateHandler(conn, iface, neighbourHandler),
                      net::detached);
    };
}

void setupWatchers(net::io_context& io_context,
                   const std::shared_ptr<sdbusplus::asio::connection>& conn,
                   const ApplicationConfig& config,
                   BmcPairingManagerObject& controller,
                   std::shared_ptr<BmcResponder>& bmcResponder)
{
    // Attestation state watcher
    DbusSignalWatcher<bool>::watch(
        io_context, conn,
        std::bind_front(onSpdmStateChange, std::ref(io_context), config.port,
                        std::ref(controller), std::ref(bmcResponder)),
        ATTESTATION_RES_INTF, ATTESTATION_RES_SIGNAL);

    // Neighbour discovery
    auto neighbourHandler =
        createNeighbourHandler(io_context, controller, config.port);
    auto fallbackHandler = createFallbackHandler(
        io_context, conn, config.interface_id, neighbourHandler);

    DbusSignalWatcher<sdbusplus::message_t>::watch(
        io_context, conn,
        makeNeighbourDiscoveryHandler(neighbourHandler,
                                      std::move(fallbackHandler)),
        sdbusplus::bus::match::rules::interfacesAddedAtPath(
            std::format(LLDP_REC_PATH, config.interface_id)));

    // Initial neighbour update
    net::co_spawn(
        io_context,
        makeNeighbourUpdateHandler(conn, config.interface_id, neighbourHandler),
        net::detached);
}

int main(int argc, const char* argv[])
{
    auto [conf] = getArgs(parseCommandline(argc, argv), "--conf,-c");
    if (!conf)
    {
        LOG_ERROR(
            "No config file provided :eg provisioningd --conf /path/to/conf");

        return 1;
    }
    try
    {
        auto& logger = getLogger();
        logger.setLogLevel(LogLevel::INFO);
#ifdef USE_TPM_CERTIFICATE
        // Only load the tpm2 provider for TPM builds.  Explicitly loading any
        // provider disables OpenSSL's implicit "default" provider, which
        // leaves non-TPM builds with no ciphers (SSL_CTX_new fails).
        Tpm2::getInstance(); // Initialize TPM2 provider
#endif
        net::io_context io_context;

        auto config = loadAndValidateConfig(std::string(conf.value()));

        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);
        BmcPairingManagerObject controller(io_context, conn);
        conn->request_name(BmcPairingManagerObject::busName);

        // Create object server for D-Bus interfaces
        auto objServer = std::make_shared<sdbusplus::asio::object_server>(conn);

        // Create debug controller for runtime log level control
        DebugController debugController(conn, objServer);

        auto bmcResponder =
            initializeResponder(io_context, config.port, controller);

        controller.setPairingHandler(createPairingHandler(
            io_context, conn, config.port, config.interface_id, controller,
            bmcResponder));

        setupWatchers(io_context, conn, config, controller, bmcResponder);

        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
        return 1;
    }

    return 0;
}
