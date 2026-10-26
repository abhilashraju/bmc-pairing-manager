

#include "attestation_handshake.hpp"
#include "attestationdeviceiface.hpp"
#include "attestationresponderiface.hpp"
#include "certificate_exchange.hpp"
#include "command_line_parser.hpp"
#include "dbusproperty_watcher.hpp"
#include "debug_controller.hpp"
#include "eventmethods.hpp"
#include "eventqueue.hpp"
#include "lldp_neighbour_handlers.hpp"
#include "logger.hpp"
#include "root_certs.hpp"
#include "sdbus_calls.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <nlohmann/json.hpp>

#include <csignal>

static constexpr auto LLDP_PATH = "/xyz/openbmc_project/network/lldp/{}";
static constexpr auto LLDP_PROP = "ManagementAddressIPv4";
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::string prefix;
ssl::context loadServerContext(const std::string& servercert,
                               const std::string& privKey,
                               const std::string& trustStore, bool selfsigned)
{
    ssl::context ssl_server_context(ssl::context::sslv23_server);

    // Load server certificate and private key
    ssl_server_context.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);
    ssl_server_context.load_verify_file(trustStore);
    if (selfsigned)
    {
        ssl_server_context.set_verify_mode(boost::asio::ssl::verify_none);
    }
    else
    {
        ssl_server_context.set_verify_mode(boost::asio::ssl::verify_peer);
    }
    ssl_server_context.use_certificate_chain_file(servercert);
    ssl_server_context.use_private_key_file(privKey,
                                            boost::asio::ssl::context::pem);
    return ssl_server_context;
}
void combineContexts(ssl::context& defaultCtx,
                     std::map<std::string, SSL_CTX*>& ctxMap)
{
    SSL_CTX* raw_default = defaultCtx.native_handle();

    SSL_CTX_set_client_hello_cb(
        raw_default,
        [](SSL* s, int* /*al*/, void* arg) {
            std::map<std::string, SSL_CTX*>& virtualHosts =
                *(static_cast<std::map<std::string, SSL_CTX*>*>(arg));
            const char* servername =
                SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
            if (servername)
            {
                // 2. Look up the correct SSL_CTX in your map
                auto it = virtualHosts.find(servername);
                if (it != virtualHosts.end())
                {
                    SSL_CTX* new_ctx = it->second;
                    // 3. Switch the SSL object to the new context
                    SSL_set_SSL_CTX(s, new_ctx);
                    std::cout
                        << "Switched to SSL_CTX for hostname: " << servername
                        << '\n';
                    return SSL_CLIENT_HELLO_SUCCESS;
                }
            }
            return SSL_CLIENT_HELLO_SUCCESS;
        },
        &ctxMap);
}
ssl::context loadClientContext(const std::string& clientcert,
                               const std::string& privKey,
                               const std::string& caCert, bool selfsigned)
{
    ssl::context ssl_client_context(ssl::context::sslv23_client);
    ssl_client_context.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);
    ssl_client_context.load_verify_file(caCert);
    if (selfsigned)
    {
        ssl_client_context.set_verify_mode(boost::asio::ssl::verify_none);
    }
    else
    {
        ssl_client_context.set_verify_mode(boost::asio::ssl::verify_peer);
    }
    ssl_client_context.use_certificate_chain_file(clientcert);
    ssl_client_context.use_private_key_file(privKey,
                                            boost::asio::ssl::context::pem);
    return ssl_client_context;
}
void intialiseAttestationHandler(
    AttestationHandler& attestationHandler, AttestationDeviceIface& deviceIface,
    AttestationResponderIface& attestationResponder)
{
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    attestationHandler.setAttestationFinishHandler([&](bool status, bool resp)
                                                       -> net::awaitable<void> {
        LOG_INFO(
            "Attestation Handshake finished with status: {} is-responder {}",
            status, resp);
        if (resp)
        {
            attestationResponder.emitStatus(status);
        }
        else
        {
            deviceIface.emitStatus(status);
        }
        co_return;
    });
}

auto createNeighbourHandler(
    net::io_context& io_context,
    const std::shared_ptr<sdbusplus::asio::connection>& conn,
    sdbusplus::asio::object_server& dbusServer,
    AttestationHandler& attestationHandler,
    AttestationResponderIface& attestationResponder,
    std::shared_ptr<AttestationDeviceIface>& attestationDevice,
    const std::string& remotePort)
{
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    return [&io_context, conn, &dbusServer, &attestationHandler,
            &attestationResponder, &attestationDevice, remotePort](
               std::string address, std::string name) -> net::awaitable<void> {
        LOG_INFO("Neighbour LLDP Address : {} Name : {} ", address, name);
        std::string sanitizedName = "peer";
        std::replace(sanitizedName.begin(), sanitizedName.end(), '-', '_');
        AttestationDeviceIface::ResponderInfo responderInfo{
            sanitizedName, address, remotePort};
        attestationDevice.reset();
        attestationDevice = std::make_shared<AttestationDeviceIface>(
            conn, dbusServer, responderInfo, attestationHandler);
        intialiseAttestationHandler(attestationHandler, *attestationDevice,
                                    attestationResponder);
        co_return;
    };
}
nlohmann::json loadConfig(const std::string& configPath)
{
    std::ifstream confFile(configPath);
    if (confFile)
    {
        return nlohmann::json::parse(confFile);
    }
    return nlohmann::json{
        {"server-cert", std::string{"/etc/ssl/certs/https/server.mtls.pem"}},
        {"server-pkey", std::string{"/etc/ssl/private/server.mtls.key"}},
        {"client-cert", std::string{"/etc/ssl/certs/https/client.mtls.pem"}},
        {"client-pkey", std::string{"/etc/ssl/private/client.mtls.key"}},
        {"sign-privkey", std::string{"/etc/ssl/private/signing.key"}},
        {"sign-cert", std::string{"/etc/ssl/certs/https/signing.pem"}},
        {"verify-cert", std::string{"/etc/ssl/certs/bmc.ca.pem"}},
        {"self-signed", true},
        {"port", 8091},
        {"ip", std::string{"0.0.0.0"}},
        {"interface_id", std::string{"eth2"}},
        {"exchange_prefix", std::string{"/"}},
        {"resources", nlohmann::json::array()}};
}
int main(int argc, const char* argv[])
{
    auto [conf] = getArgs(parseCommandline(argc, argv), "--conf,-c");
    if (!conf)
    {
        LOG_ERROR(
            "No config file provided :eg event_broker --conf /path/to/conf");

        return 1;
    }
    try
    {
        auto json = loadConfig(std::string(conf.value()));

        auto servercert = json.value(
            "server-cert", std::string{"/etc/ssl/certs/https/server.mtls.pem"});
        auto serverprivkey = json.value(
            "server-pkey", std::string{"/etc/ssl/private/server.mtls.key"});
        auto clientcert = json.value(
            "client-cert", std::string{"/etc/ssl/certs/https/client.mtls.pem"});
        auto clientprivkey = json.value(
            "client-pkey", std::string{"/etc/ssl/private/client.mtls.key"});
        auto signprivkey = json.value(
            "sign-privkey", std::string{"/etc/ssl/private/signing.key"});
        auto signcert = json.value(
            "sign-cert", std::string{"/etc/ssl/certs/https/signing.pem"});
        auto caCert =
            json.value("verify-cert", std::string{"/etc/ssl/certs/bmc.ca.pem"});
        auto self_signed = json.value("self-signed", false);
        auto port = json.value("port", 8091);
        auto myip = json.value("ip", std::string{"0.0.0.0"});
        auto iface = json.value("interface_id", std::string{"eth2"});
        prefix = json.value("exchange_prefix", std::string{"/"});
        std::vector<std::string> resources =
            json.value("resources", std::vector<std::string>{});
        auto maxConnections = 1;

        auto& logger = reactor::getLogger();
        logger.setLogLevel(reactor::LogLevel::INFO);
        net::io_context io_context;
        if (!ensureCertificates(servercert, self_signed))
        {
            LOG_ERROR("Failed to ensure server certificates");
            return 1;
        }
        ssl::context ssl_client_context =
            loadClientContext(clientcert, clientprivkey, caCert, self_signed);
        auto serverCtx =
            loadServerContext(servercert, serverprivkey, caCert, self_signed);
        TcpStreamType acceptor(io_context.get_executor(), myip,
                               static_cast<short>(port), serverCtx);
        EventQueue eventQueue(io_context.get_executor(), acceptor,
                              ssl_client_context, maxConnections);
        auto conn = std::make_shared<sdbusplus::asio::connection>(io_context);

        auto verifyCert = loadCertificate(signcert);
        if (!verifyCert)
        {
            LOG_ERROR("Failed to load signing certificate from {}", signcert);
            return 1;
        }
        makeDefaultCertStrategy()->create("bmc.peer");
        AttestationHandler attestationHandler(
            MeasurementTaker(loadPrivateKey(signprivkey)),
            MeasurementVerifier(getPublicKeyFromCert(verifyCert)), eventQueue,
            io_context);
        if (!self_signed) // skip mesauement for self signed certs
        {
            for (const auto& resource : resources)
            {
                attestationHandler.addToMeasure(resource);
            }
        }
        sdbusplus::asio::object_server dbusServer(conn);

        // Create object server for D-Bus interfaces
        auto objServer = std::make_shared<sdbusplus::asio::object_server>(conn);

        // Create debug controller for runtime log level control
        DebugController debugController(conn, objServer);

        std::shared_ptr<AttestationDeviceIface> attestationDevice;
        AttestationResponderIface attestationResponder(conn, dbusServer,
                                                       "responder1");

        auto neighbourHandler = createNeighbourHandler(
            io_context, conn, dbusServer, attestationHandler,
            attestationResponder, attestationDevice, std::format("{}", port));
        auto fallbackHandler = [&io_context, conn, iface, neighbourHandler]() {
            net::co_spawn(
                io_context,
                makeNeighbourUpdateHandler(conn, iface, neighbourHandler),
                net::detached);
        };
        DbusSignalWatcher<sdbusplus::message_t>::watch(
            io_context, conn,
            makeNeighbourDiscoveryHandler(neighbourHandler,
                                          std::move(fallbackHandler)),
            sdbusplus::bus::match::rules::interfacesAddedAtPath(
                std::format(LLDP_REC_PATH, iface)));

        net::co_spawn(io_context,
                      makeNeighbourUpdateHandler(conn, iface, neighbourHandler),
                      net::detached);
        conn->request_name(AttestationDeviceIface::busName);

        // In Simics mode all TPM certs are seeded at startup (no handshake
        // needed).  Emit the Attested signal immediately so bmc-pairing-manager
        // can build its SSL context and start listening without waiting for a
        // real attestation exchange.
        if (isSimics())
        {
            net::post(io_context, [&attestationResponder]() {
                LOG_INFO(
                    "Simics mode: emitting Attested signal (certs pre-seeded)");
                attestationResponder.emitStatus(true);
            });
        }

        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Exception: {}", e.what());
    }
    return 0;
}
