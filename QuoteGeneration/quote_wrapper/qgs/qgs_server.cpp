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
#include "qgs.message.pb.h"
#include "qgs_log.h"
#include "qgs_msg_wrapper.h"
#include "se_trace.h"
#include "td_ql_wrapper.h"
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/cstdint.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/tss.hpp>
#include <boost/unordered_set.hpp>
#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;
using boost::uint8_t;
using namespace qgs::message;
static const int QGS_TIMEOUT = 30;

namespace intel { namespace sgx { namespace dcap { namespace qgs {

void cleanup(tee_att_config_t *p_ctx) {
    QGS_LOG_INFO("About to delete ctx in cleanup\n");
    tee_att_free_context(p_ctx);
    return;
}
boost::thread_specific_ptr<tee_att_config_t> ptr(cleanup);

class QgsConnection : public boost::enable_shared_from_this<QgsConnection> {
  public:
    using Pointer = boost::shared_ptr<QgsConnection>;
    using RequestPointer = boost::shared_ptr<Request>;
    using ResponsePointer = boost::shared_ptr<Response>;
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
        start_read_header();
    }

    void stop() {
        boost::system::error_code ec;
        QGS_LOG_INFO("About to shutdown and close socket\n");
        m_socket.shutdown(asio::socket_base::shutdown_both, ec);
        m_socket.close();
        {
            boost::lock_guard<boost::mutex> lock(m_connection_mtx);
            m_connections.erase(shared_from_this());
            QGS_LOG_INFO("erased a connection, now [%d]\n", m_connections.size());
        }
    }

  private:
    boost::mutex &m_connection_mtx;
    ConnectionSet &m_connections;
    asio::thread_pool &m_pool;
    gs::socket m_socket;
    asio::deadline_timer m_timer;
    vector<uint8_t> m_readbuf;
    QgsMsgWrapper<Request> m_packed_request;

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
          m_timer(io_service),
          m_packed_request(boost::shared_ptr<Request>(new Request())) {
    }

    void handle_read_header(const boost::system::error_code &ec) {
        std::ostringstream oss;
        oss << ec.category().name() << ':' << ec.value();
        QGS_LOG_INFO("handle read header, status [%s]\n",
                     oss.str().c_str());
        if (!ec) {
            QGS_LOG_INFO("Got header!\n");
            unsigned msg_len = m_packed_request.decode_header(m_readbuf);
            QGS_LOG_INFO("body should be [%d] bytes!\n", msg_len);
            start_read_body(msg_len);
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
        if (m_packed_request.unpack(m_readbuf)) {
            std::ostringstream oss;
            oss << boost::this_thread::get_id();
            QGS_LOG_INFO("unpack message successfully in thread [%s]\n",
                         oss.str().c_str());
            RequestPointer req = m_packed_request.get_msg();
            asio::post(m_pool, [this, self = shared_from_this(), req] {
                boost::system::error_code ec;
                ResponsePointer resp = prepare_response(req);

                vector<uint8_t> writebuf;
                QgsMsgWrapper<Response> resp_msg(resp);
                resp_msg.pack(writebuf);
                std::ostringstream oss1;
                oss1 << boost::this_thread::get_id();
                QGS_LOG_INFO("About to write response in thread [%s]\n",
                             oss1.str().c_str());
                asio::write(m_socket, asio::buffer(writebuf), ec);
                m_timer.cancel();
                stop();
            });
        }
    }

    void start_read_header() {
        m_readbuf.resize(HEADER_SIZE);
        asio::async_read(m_socket, asio::buffer(m_readbuf),
                         boost::bind(&QgsConnection::handle_read_header,
                                     shared_from_this(),
                                     asio::placeholders::error));
    }

    void start_read_body(unsigned msg_len) {
        m_readbuf.resize(HEADER_SIZE + msg_len);
        asio::mutable_buffers_1 buf = asio::buffer(&m_readbuf[HEADER_SIZE],
                                                   msg_len);
        asio::async_read(m_socket, buf,
                         boost::bind(&QgsConnection::handle_read_body,
                                     shared_from_this(),
                                     asio::placeholders::error));
    }

    ResponsePointer prepare_response(RequestPointer req) {
        ResponsePointer resp(new Response);
        tee_att_error_t tee_att_ret = TEE_ATT_SUCCESS;

        QGS_LOG_INFO("enter prepare_response\n");
        if (ptr.get() == 0) {
            tee_att_error_t ret = TEE_ATT_SUCCESS;
            tee_att_config_t *p_ctx = NULL;
            QGS_LOG_INFO("call tee_att_create_context\n");
            ret = tee_att_create_context(NULL, NULL, &p_ctx);
            if (TEE_ATT_SUCCESS == ret) {
                std::ostringstream oss;
                oss << boost::this_thread::get_id();
                QGS_LOG_INFO("create context in thread[%s]\n",
                             oss.str().c_str());
                ptr.reset(p_ctx);
            } else {
                QGS_LOG_ERROR("Cannot create context\n");
            }
        }

        switch (req->type()) {
        case Request::MsgCase::kGetQuoteRequest: {
            uint32_t size = 0;
            vector<uint8_t> quote_buf;
            auto get_quote_resp = new Response::GetQuoteResponse();
            resp->set_type(Response::kGetQuoteResponse);

            sgx_target_info_t qe_target_info;
            uint8_t hash[32] = {0};
            size_t hash_size = sizeof(hash);
            int retry = 1;

            do {
                QGS_LOG_INFO("call tee_att_init_quote\n");
                tee_att_ret = tee_att_init_quote(ptr.get(), &qe_target_info, false,
                                                 &hash_size,
                                                 hash);
                if (TEE_ATT_SUCCESS != tee_att_ret) {
                    get_quote_resp->set_error_code(1);
                    QGS_LOG_ERROR("tee_att_init_quote return 0x%x\n", tee_att_ret);
                } else if (TEE_ATT_SUCCESS != (tee_att_ret = tee_att_get_quote_size(ptr.get(), &size))) {
                    get_quote_resp->set_error_code(1);
                    QGS_LOG_ERROR("tee_att_get_quote_size return 0x%x\n", tee_att_ret);
                } else {
                    quote_buf.resize(size);
                    tee_att_ret = tee_att_get_quote(ptr.get(),
                                                    (uint8_t *)req->getquoterequest().report().c_str(),
                                                    (uint32_t)req->getquoterequest().report().length(),
                                                    NULL,
                                                    quote_buf.data(),
                                                    size);
                    if (TEE_ATT_SUCCESS != tee_att_ret) {
                        get_quote_resp->set_error_code(1);
                        QGS_LOG_ERROR("tee_att_get_quote return 0x%x\n", tee_att_ret);
                    } else {
                        get_quote_resp->set_error_code(0);
                        get_quote_resp->set_quote(quote_buf.data(), size);
                        QGS_LOG_INFO("tee_att_get_quote return Success\n");
                    }
                }
            // Only return once when the return code is TEE_ATT_ATT_KEY_NOT_INITIALIZED
            } while (TEE_ATT_ATT_KEY_NOT_INITIALIZED == tee_att_ret && retry--);
            resp->set_allocated_getquoteresponse(get_quote_resp);
            QGS_LOG_INFO("byte length is: %d\n", resp->ByteSize());
            break;
        }
        default:
            QGS_LOG_ERROR("Whoops, bad request!");
            break;
        }

        return resp;
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
                    QGS_LOG_INFO("Added a new connection, now [%d]\n", connections.size());
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
