#pragma once
#include "make_awaitable.hpp"
#include "socket_streams.hpp"

#include <openssl/err.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/system/error_code.hpp>

#include <iostream>
#include <string>
#include <utility>

namespace NSNAME
{
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

inline AwaitableResult<net::ip::tcp::resolver::results_type> awaitable_resolve(
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-reference-coroutine-parameters)
    typename net::ip::tcp::resolver& resolver, std::string host,
    std::string port)
{
    auto h = make_awaitable_handler<net::ip::tcp::resolver::results_type>(
        [&](auto promise) {
            // resolver.async_resolve(
            //     host, port,
            //     [handler = std::move(handler)](
            //         boost::system::error_code ec,
            //         net::ip::tcp::resolver::results_type results) mutable
            //         { handler(ec, std::move(results));
            //     });
            boost::system::error_code ec;
            auto results = resolver.resolve(host, port, ec);
            promise.setValues(ec, results);
        });
    co_return co_await h();
}
class TcpClient
{
  public:
    TcpClient(net::any_io_executor io_context, ssl::context& ssl_context) :
        resolver_(io_context),
        stream_(std::make_shared<ssl::stream<tcp::socket>>(io_context,
                                                           ssl_context)),
        timer_(std::make_shared<net::steady_timer>(io_context))
    {}
    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;
    TcpClient(TcpClient&&) = delete;
    TcpClient& operator=(TcpClient&&) = delete;
    ~TcpClient() noexcept
    {
        try
        {
            timer_->cancel();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Exception in TcpClient destructor: {}", e.what());
        }
    }

    net::awaitable<boost::system::error_code> connect(
        std::string host, std::string port, std::string sniHost = {})
    {
        // NOLINTNEXTLINE(clang-analyzer-core.NullDereference)
        auto [ec, results] = co_await awaitable_resolve(resolver_, host, port);
        if (ec)
        {
            LOG_ERROR("Error resolving {}:{}. Error: {}", host, port,
                      ec.message());
            co_return ec;
        }

        TimedStreamer streamer(stream_, timer_);
        streamer.setTimeout(30s);
        co_await net::async_connect(
            stream_->next_layer(), results,
            net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("Error connecting to {}:{}. Error: {}", host, port,
                      ec.message());
            co_return ec;
        }

        // Configure TCP keepalive to detect dead connections quickly
        configureSocketKeepalive(stream_->lowest_layer());

        // Set SNI hostname for TLS handshake (fall back to host if not given)
        const std::string& sni = sniHost.empty() ? host : sniHost;
        if (!SSL_set_tlsext_host_name(stream_->native_handle(), sni.c_str()))
        {
            LOG_WARNING("Failed to set SNI hostname for {}", sni);
        }

        streamer.setTimeout(30s);
        co_await stream_->async_handshake(
            ssl::stream_base::client,
            net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            logSslHandshakeError(host, port, ec);
            co_return ec;
        }
        co_return ec;
    }

    AwaitableResult<std::size_t> write(net::const_buffer data)
    {
        TimedStreamer streamer(stream_, timer_);
        co_return co_await streamer.write(data, true);
    }

    AwaitableResult<std::size_t> read(net::mutable_buffer buffer)
    {
        TimedStreamer streamer(stream_, timer_);
        co_return co_await streamer.read(buffer, true);
    }
    ssl::stream<tcp::socket>& stream()
    {
        return *stream_;
    }
    TimedStreamer<ssl::stream<tcp::socket>> streamer()
    {
        return {stream_, timer_};
    }
    void close() noexcept
    {
        boost::system::error_code ec;
        stream_->next_layer().close(ec); // NOLINT(bugprone-unused-return-value)
        if (ec)
        {
            LOG_ERROR("Error closing socket: {}", ec.message());
        }
    }
    bool isOpen() const
    {
        return stream_->lowest_layer().is_open();
    }

  private:
    tcp::resolver resolver_;
    std::shared_ptr<ssl::stream<tcp::socket>> stream_;
    std::shared_ptr<net::steady_timer> timer_;
};
} // namespace NSNAME
