/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "qgs_server.h"
#include "qgs_log.h"
#include "qgs_ql_logic.h"
#include "qgs_msg_lib.h"
#include "se_trace.h"
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/cstdint.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/smart_ptr/make_shared_array.hpp>
#include <boost/thread.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/unordered_set.hpp>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;
using boost::uint8_t;
static const int QGS_TIMEOUT = 30;

namespace intel { namespace sgx { namespace dcap { namespace qgs {

const unsigned HEADER_SIZE = 4;

uint32_t decode_header(const data_buffer &buf) {
    if (buf.size() < HEADER_SIZE) {
        return 0;
    }
    uint32_t msg_size = 0;
    for (uint32_t i = 0; i < HEADER_SIZE; ++i) {
        msg_size = msg_size * 256 + (static_cast<uint32_t>(buf[i]) & 0xFF);
    }
    return msg_size;
}

void encode_header(data_buffer &buf, uint32_t size) {
    assert(buf.size() >= HEADER_SIZE);
    buf[0] = static_cast<boost::uint8_t>((size >> 24) & 0xFF);
    buf[1] = static_cast<boost::uint8_t>((size >> 16) & 0xFF);
    buf[2] = static_cast<boost::uint8_t>((size >> 8) & 0xFF);
    buf[3] = static_cast<boost::uint8_t>(size & 0xFF);
}

class QgsConnection : public boost::enable_shared_from_this<QgsConnection> {
  public:
    using Pointer = boost::shared_ptr<QgsConnection>;
    using ConnectionSet = boost::unordered_set<Pointer>;
    static Pointer create(boost::mutex &connection_mtx,
                          ConnectionSet &connections,
                          asio::thread_pool &pool,
                          asio::io_service &io_service) {
        return Pointer(new QgsConnection(connection_mtx, connections, pool,
                                         io_service));
    }

    gs::socket &get_socket() {
        return m_socket;
    }

    void start() {
        m_timer.expires_from_now(timeout);
        m_timer.async_wait([this](boost::system::error_code ec) {
            if (!ec) {
                QGS_LOG_ERROR("timeout\n");
                stop();
            }
        });
        start_read();
    }

    void stop() {
        boost::system::error_code ec;
        QGS_LOG_INFO("About to shutdown and close socket\n");
        m_socket.shutdown(asio::socket_base::shutdown_both, ec);
        m_socket.close();
        {
            boost::lock_guard<boost::mutex> lock(m_connection_mtx);
            m_connections.erase(shared_from_this());
            QGS_LOG_INFO("erased a connection, now [%zu]\n", m_connections.size());
        }
    }

  private:
    boost::mutex &m_connection_mtx;
    ConnectionSet &m_connections;
    asio::thread_pool &m_pool;
    gs::socket m_socket;
    asio::deadline_timer m_timer;
    data_buffer m_readbuf;

    const boost::posix_time::time_duration timeout =
        boost::posix_time::seconds(QGS_TIMEOUT);

    QgsConnection(boost::mutex &connection_mtx,
                  ConnectionSet &connections,
                  asio::thread_pool &pool,
                  asio::io_service &io_service)
        : m_connection_mtx(connection_mtx),
          m_connections(connections),
          m_pool(pool),
          m_socket(io_service),
          m_timer(io_service) {
    }

    void handle_read(const boost::system::error_code &ec, std::size_t bytes_transferred) {
        std::ostringstream oss;
        oss << ec.category().name() << ':' << ec.value();
        QGS_LOG_INFO("handle_read: status [%s]\n",
                     oss.str().c_str());
        if (ec == asio::error::eof) {
            oss << "Received eof and " << bytes_transferred << " bytes.";
            QGS_LOG_INFO("handle_read:[%s]\n", oss.str().c_str());
        } else if (ec) {
            oss << "Error: " << ec.message();
            QGS_LOG_INFO("handle_read:[%s]\n", oss.str().c_str());
        } else {
            oss << "Received " << bytes_transferred << " bytes.";
            QGS_LOG_INFO("handle_read:[%s]\n", oss.str().c_str());

            unsigned msg_len = decode_header(m_readbuf);
            uint32_t msg_type = QGS_MSG_TYPE_MAX;
            auto ptr = reinterpret_cast<qgs_msg_header_t *>(&m_readbuf[HEADER_SIZE]);
            if (!msg_len
                || ptr->size != msg_len
                || QGS_MSG_SUCCESS != qgs_msg_get_type(&m_readbuf[HEADER_SIZE],
                        (uint32_t)bytes_transferred - HEADER_SIZE, &msg_type)) {
                const std::size_t raw_report_size = 1024;
                if (bytes_transferred == raw_report_size) {
                    QGS_LOG_INFO("process raw request [%zu] bytes!.\n", bytes_transferred);
                    m_readbuf.resize(bytes_transferred);
                    handle_raw_request();
                } else {
                    QGS_LOG_INFO("wait for [%zu] bytes!.\n", raw_report_size - bytes_transferred);
                    asio::async_read(m_socket, asio::buffer(m_readbuf),
                                     asio::transfer_exactly(raw_report_size - bytes_transferred),
                                     boost::bind(&QgsConnection::handle_read,
                                                 shared_from_this(),
                                                 asio::placeholders::error,
                                                 asio::placeholders::bytes_transferred));
                }
                return;
            } else {
                if (msg_len + HEADER_SIZE > bytes_transferred) {
                    QGS_LOG_INFO("wait for [%zu] bytes!.\n", msg_len + HEADER_SIZE - bytes_transferred);
                    asio::async_read(m_socket, asio::buffer(m_readbuf),
                                     asio::transfer_exactly(msg_len + HEADER_SIZE - bytes_transferred),
                                     boost::bind(&QgsConnection::handle_read,
                                                 shared_from_this(),
                                                 asio::placeholders::error,
                                                 asio::placeholders::bytes_transferred));
                } else {
                    QGS_LOG_INFO("process legecy request [%zu] bytes!.\n", bytes_transferred);
                    m_readbuf.resize(bytes_transferred);
                    handle_request();
                    return;
                }
            }
        }
    }

    void handle_read_body(const boost::system::error_code &ec) {
        std::ostringstream oss;
        oss << ec.category().name() << ':' << ec.value();
        QGS_LOG_INFO("handle read body status [%s]\n",
                     oss.str().c_str());
        if (!ec) {
            QGS_LOG_INFO("Got body!\n");
            handle_request();
        }
    }

    void handle_request() {
        std::ostringstream oss;
        oss << boost::this_thread::get_id();
        QGS_LOG_INFO("unpack message successfully in thread [%s]\n",
                        oss.str().c_str());
        asio::post(m_pool, [this, self = shared_from_this()] {
            boost::system::error_code ec;

            data_buffer resp = prepare_response(const_cast<data_buffer &>(m_readbuf));

            uint32_t resp_size = (uint32_t)resp.size();
            if (!resp_size) {
                QGS_LOG_ERROR("resp_size is 0");
                m_timer.cancel();
                stop();
                return;
            }
            data_buffer writebuf;
            writebuf.resize(HEADER_SIZE + resp_size);
            encode_header(writebuf, resp_size);
            std::copy(resp.begin(), resp.end(), writebuf.begin() + HEADER_SIZE);
            std::ostringstream oss1;
            oss1 << boost::this_thread::get_id();
            QGS_LOG_INFO("About to write response in thread [%s]\n", oss1.str().c_str());
            if (asio::write(m_socket, asio::buffer(writebuf), ec) != writebuf.size()) {
                QGS_LOG_INFO("Failed to write all buffer in thread [%s]\n", oss1.str().c_str());
            }
            m_timer.cancel();
            stop();
        });
    }

    void handle_raw_request() {
        std::ostringstream oss;
        oss << boost::this_thread::get_id();
        QGS_LOG_INFO("unpack message successfully in thread [%s]\n",
                     oss.str().c_str());
        asio::post(m_pool, [this, self = shared_from_this()] {
            boost::system::error_code ec;

            data_buffer resp = prepare_raw_response(const_cast<data_buffer &>(m_readbuf));

            uint32_t resp_size = (uint32_t)resp.size();
            if (!resp_size) {
                QGS_LOG_INFO("resp_size is 0");
                m_timer.cancel();
                stop();
                return;
            }
            std::ostringstream oss1;
            oss1 << boost::this_thread::get_id();
            QGS_LOG_INFO("About to write response in thread [%s]\n", oss1.str().c_str());
            if (asio::write(m_socket, asio::buffer(resp), ec) != resp.size()) {
                QGS_LOG_INFO("Failed to write all buffer in thread [%s]\n", oss1.str().c_str());
            }
            m_timer.cancel();
            stop();
        });
    }


    void start_read() {
        m_readbuf.resize(4096);
        asio::async_read(m_socket, asio::buffer(m_readbuf),
                         asio::transfer_at_least(HEADER_SIZE + sizeof(qgs_msg_header_t)),
                         boost::bind(&QgsConnection::handle_read,
                                     shared_from_this(),
                                     asio::placeholders::error,
                                     asio::placeholders::bytes_transferred));
    }

    data_buffer prepare_response(data_buffer const &req) {
        return get_resp(&req[HEADER_SIZE], (uint32_t)req.size() - HEADER_SIZE);
    }

    data_buffer prepare_raw_response(data_buffer const &req) {
        return get_raw_resp(req.data(), (uint32_t)req.size());
    }
};


    struct QgsServer::QgsServerImpl
    {
        using vsock_acceptor = asio::basic_socket_acceptor<gs>;
        boost::mutex connection_mtx;
        boost::unordered_set<boost::shared_ptr<QgsConnection>> connections;
        boost::asio::thread_pool pool;
        QgsServerImpl(asio::io_service &in_io_service, gs::endpoint &ep, uint8_t num_threads)
            : pool(num_threads), acceptor(in_io_service, ep), io_service(in_io_service) {
            start_accept();
        }

        void start_accept()
        {
            QgsConnection::Pointer new_connection =
                QgsConnection::create(connection_mtx, connections, pool,
                                      io_service);

            acceptor.async_accept(new_connection->get_socket(),
                                  boost::bind(&QgsServerImpl::handle_accept,
                                              this, new_connection,
                                              asio::placeholders::error));
        }

        void handle_accept(QgsConnection::Pointer connection,
                           const boost::system::error_code& ec) {
            if (!ec) {
                {
                    boost::lock_guard<boost::mutex> lock(connection_mtx);
                    connections.insert(connection);
                    QGS_LOG_INFO("Added a new connection, now [%zu]\n", connections.size());
                }
                connection->start();
                start_accept();
            }
        }

        void shutdown() {
            QGS_LOG_INFO("About to close acceptor\n");
            acceptor.close();
            std::vector<boost::shared_ptr<QgsConnection>> connections_to_close;
            int i = 0;
            copy(connections.begin(), connections.end(), back_inserter(connections_to_close));
            for (auto& s : connections_to_close) {
                i++;
                s->stop();
            }
            QGS_LOG_INFO("Stopped [%d] connections, about to clear connection list\n", i);
            pool.join();
            QGS_LOG_INFO("Joined thread pool\n");
            io_service.stop();
            QGS_LOG_INFO("Stopped io_service\n");
            connections.clear();
        }

    private:
        vsock_acceptor acceptor;
        asio::io_service& io_service;
    };

    QgsServer::QgsServer(asio::io_service &io_service, gs::endpoint &ep, uint8_t num_threads)
        : d(new QgsServerImpl(io_service, ep, num_threads)) {
    }

    void QgsServer::shutdown() {
        d->shutdown();
    }

    QgsServer::~QgsServer() {
    }

}}}}
