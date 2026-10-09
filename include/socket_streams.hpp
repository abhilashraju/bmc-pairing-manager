#pragma once
#include "beastdefs.hpp"
#include "logger.hpp"
#include "make_awaitable.hpp"

#include <openssl/err.h>

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <format>
#include <string>
#include <string_view>

#ifdef __linux__
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

using namespace std::chrono_literals;
namespace NSNAME
{
// Logs a detailed SSL handshake error.
// Boost.Asio captures only one OpenSSL error in ec.value(); the full chain is
// in the thread-local OpenSSL error queue. We drain the queue here so every
// pending error is logged before anything else clears it.
inline void logSslHandshakeError(std::string_view contextMsg,
                                 const boost::system::error_code& ec)
{
    LOG_ERROR("{}: {}", contextMsg, ec.message());

    unsigned long err = 0;
    bool anyQueued = false;
    while ((err = ERR_get_error()) != 0)
    {
        anyQueued = true;
        std::array<char, 256> buf{};
        ERR_error_string_n(err, buf.data(), buf.size());
        LOG_ERROR("  openssl: {}", buf.data());
    }

    // If the queue was already drained (consumed by asio internally), fall back
    // to decoding ec.value() directly — it holds the last captured error long.
    if (!anyQueued)
    {
        unsigned long sslErr = static_cast<unsigned long>(ec.value());
        std::array<char, 256> buf{};
        ERR_error_string_n(sslErr, buf.data(), buf.size());
        LOG_ERROR("  openssl (from ec): {}", buf.data());
    }
}

inline void logSslHandshakeError(const std::string& host,
                                 const std::string& port,
                                 const boost::system::error_code& ec)
{
    logSslHandshakeError(
        std::format("SSL handshake failed with {}:{}", host, port), ec);
}

// Configure TCP keepalive to detect dead connections quickly.
// Enables keepalive and, on Linux, sets aggressive probe parameters:
//   idle time = 3s, probe interval = 2s, probe count = 2 (~7s total).
template <typename Socket>
inline void configureSocketKeepalive(Socket& socket)
{
    boost::system::error_code ec;
    socket.set_option(boost::asio::socket_base::keep_alive(true), ec);
    if (ec)
    {
        LOG_ERROR("Failed to set keepalive option: {}", ec.message());
        return;
    }
    LOG_DEBUG("TCP keep-alive enabled");

#ifdef __linux__
    int native_fd = socket.native_handle();

    // Start sending keepalive probes after 3 seconds of idle time
    int keepalive_time = 3;
    if (setsockopt(native_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time,
                   sizeof(keepalive_time)) < 0)
    {
        LOG_ERROR("Failed to set TCP_KEEPIDLE");
    }

    // Send keepalive probes every 2 seconds
    int keepalive_interval = 2;
    if (setsockopt(native_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_interval,
                   sizeof(keepalive_interval)) < 0)
    {
        LOG_ERROR("Failed to set TCP_KEEPINTVL");
    }

    // Close connection after 2 failed probes (~7 seconds total)
    int keepalive_count = 2;
    if (setsockopt(native_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_count,
                   sizeof(keepalive_count)) < 0)
    {
        LOG_ERROR("Failed to set TCP_KEEPCNT");
    }
#endif
}

struct TcpStreamType
{
    using stream_type = boost::asio::ssl::stream<tcp::socket>;
    tcp::acceptor acceptor_;
    net::any_io_executor context;
    boost::asio::ssl::context& ssl_context_;

    TcpStreamType(const net::any_io_executor& io_context, short port,
                  boost::asio::ssl::context& ssl_context) :
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
        context(io_context), ssl_context_(ssl_context)
    {}
    TcpStreamType(const net::any_io_executor& io_context, const std::string& ip,
                  short port, boost::asio::ssl::context& ssl_context) :
        acceptor_(io_context,
                  tcp::endpoint(boost::asio::ip::make_address(ip), port)),
        context(io_context), ssl_context_(ssl_context)
    {}

    template <typename Handler>
    void accept(Handler&& handler)
    {
        auto socket = std::make_shared<stream_type>(context, ssl_context_);
        acceptor_.async_accept(
            socket->lowest_layer(),
            [this, socket, handler = std::forward<Handler>(handler)](
                boost::system::error_code ec) {
                if (!ec)
                {
                    configureSocketKeepalive(socket->lowest_layer());
                    handler(std::move(socket));
                }
            });
    }
    static auto getRemoteEndpoint(stream_type& socket)
    {
        return socket.next_layer().remote_endpoint();
    }
    auto getLocalEndpoint() const
    {
        return acceptor_.local_endpoint();
    }
    void cancel()
    {
        acceptor_.cancel();
    }
};

struct UnixStreamType
{
    using stream_type =
        boost::asio::ssl::stream<boost::asio::local::stream_protocol::socket>;
    using unix_domain = boost::asio::local::stream_protocol;
    unix_domain::acceptor acceptor_;
    net::any_io_executor context;
    boost::asio::ssl::context& ssl_context_;
    UnixStreamType(const net::any_io_executor& io_context,
                   const std::string& path,
                   boost::asio::ssl::context& ssl_context) :
        acceptor_(io_context,
                  boost::asio::local::stream_protocol::endpoint(path)),
        context(io_context), ssl_context_(ssl_context)
    {}

    template <typename Handler>
    void accept(Handler&& handler)
    {
        auto socket = std::make_shared<stream_type>(context, ssl_context_);
        acceptor_.async_accept(
            socket->lowest_layer(),
            [this, socket, handler = std::forward<Handler>(handler)](
                boost::system::error_code ec) {
                if (!ec)
                {
                    handler(std::move(socket));
                }
            });
    }
    static auto getRemoteEndpoint(stream_type& /*socket*/)
    {
        return tcp::endpoint();
    }
};

template <typename StreamType>
struct TimedStreamer
{
    TimedStreamer(std::shared_ptr<StreamType> socket,
                  std::shared_ptr<net::steady_timer> timer) :
        socket(std::move(socket)), timer(std::move(timer))
    {}
    AwaitableResult<std::size_t> read(net::mutable_buffer data,
                                      bool timeout = true)
    {
        if (timeout)
        {
            setTimeout(30s);
        }
        boost::system::error_code ec;
        auto bytes = co_await socket->async_read_some(
            data, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        timer->cancel();
        co_return std::make_pair(ec, bytes);
    }
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-reference-coroutine-parameters)
    AwaitableResult<std::size_t> readUntil(boost::asio::streambuf& buffer,
                                           std::string delim)
    {
        boost::system::error_code ec;
        auto bytes = co_await net::async_read_until(
            *socket, buffer, delim,
            boost::asio::redirect_error(net::use_awaitable, ec));
        co_return std::make_pair(ec, bytes);
    }
    AwaitableResult<std::string> readUntil(std::string delim,
                                           bool timeout = true)
    {
        boost::asio::streambuf buffer;
        if (timeout)
        {
            setTimeout(30s);
        }
        auto [ec, size] = co_await readUntil(buffer, delim);
        timer->cancel();
        if (ec)
        {
            co_return std::make_pair(ec, std::string{});
        }
        std::string ret;
        auto data = buffer.data();
        ret.append(boost::asio::buffers_begin(data),
                   boost::asio::buffers_begin(data) + size);
        co_return std::make_pair(ec, std::move(ret));
    }

    AwaitableResult<std::size_t> write(net::const_buffer data,
                                       bool timeout = true)
    {
        if (timeout)
        {
            setTimeout(30s);
        }
        boost::system::error_code ec;
        auto bytes = co_await socket->async_write_some(
            data, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        timer->cancel();
        co_return std::make_pair(ec, bytes);
    }
    void setTimeout(std::chrono::seconds timeout)
    {
        timer->expires_after(timeout);
        timer->async_wait(
            [socket = socket](const boost::system::error_code& ec) {
                if (!ec)
                {
                    socket->next_layer().cancel();
                }
            });
    }
    void close()
    {
        boost::system::error_code ec;
        socket->next_layer().close(ec);
        if (ec)
        {
            LOG_ERROR("Error closing socket: {}", ec.message());
        }
    }
    bool isOpen() const
    {
        return socket->next_layer().is_open();
    }
    std::shared_ptr<StreamType> socket;
    std::shared_ptr<net::steady_timer> timer;
};
} // namespace NSNAME
