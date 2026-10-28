#pragma once
#include "logger.hpp"
#include "tcp_server.hpp"

using namespace reactor;
using Streamer = reactor::TimedStreamer<ssl::stream<tcp::socket>>;
struct BmcResponder
{
    // Maximum allowed message size to prevent buffer overflow
    static constexpr size_t MAX_MESSAGE_SIZE = 1024;

    // Helper function to detect and log connection errors
    static bool isConnectionError(const boost::system::error_code& ec)
    {
        if (!ec)
        {
            return false; // No error
        }

        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_DEBUG("Operation timed out");
            return false; // Timeout, can continue
        }

        // Detect abrupt disconnection scenarios
        if (ec == boost::asio::error::eof)
        {
            LOG_INFO("Peer closed connection gracefully");
        }
        else if (ec == boost::asio::error::connection_reset)
        {
            LOG_WARNING("Peer connection reset (abrupt termination)");
        }
        else if (ec == boost::asio::error::broken_pipe)
        {
            LOG_WARNING("Broken pipe - peer disconnected abruptly");
        }
        else
        {
            LOG_ERROR("Connection error: {}", ec.message());
        }

        return true; // Fatal error, should disconnect
    }

    ssl::context ssl;
    TcpStreamType acceptor;
    TcpServer<TcpStreamType, BmcResponder> server;
    using WatcherCallback = std::function<void(bool)>;
    WatcherCallback watcherCallback;
    BmcResponder(net::io_context& ctx, ssl::context sslctx, short port) :
        ssl(std::move(sslctx)), acceptor(ctx.get_executor(), port, ssl),
        server(ctx.get_executor(), acceptor, *this)
    {
        LOG_INFO("BMC Responder started on port {}", port);
    }
    void onConnectionChange(WatcherCallback callback)
    {
        watcherCallback = std::move(callback);
    }
    net::awaitable<void> operator()(Streamer streamer)
    {
        // new connection
        watcherCallback(true);
        while (true)
        {
            std::array<char, MAX_MESSAGE_SIZE> data{};
            boost::system::error_code ec;
            size_t bytes{0};
            std::tie(ec, bytes) =
                co_await streamer.read(net::buffer(data), true);

            // Check for connection errors (timeouts will continue, fatal errors
            // will disconnect)
            if (isConnectionError(ec))
            {
                if (watcherCallback)
                {
                    watcherCallback(false);
                }
                co_return;
            }

            // Validate message size
            if (bytes > MAX_MESSAGE_SIZE)
            {
                LOG_ERROR(
                    "Received message size {} exceeds maximum allowed size {}",
                    bytes, MAX_MESSAGE_SIZE);
                if (watcherCallback)
                {
                    watcherCallback(false);
                }
                co_return;
            }

            LOG_DEBUG("Received: {}", std::string(data.data(), bytes));
            std::string response = "alive";
            std::tie(ec, bytes) =
                co_await streamer.write(net::buffer(response), true);

            // Check for fatal connection errors during write
            if (isConnectionError(ec))
            {
                if (watcherCallback)
                {
                    watcherCallback(false);
                }
                co_return;
            }
        }
    }
};
