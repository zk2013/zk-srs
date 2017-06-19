/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2017 OSSRS(winlin)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <srs_app_mars_conn.hpp>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_server.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_app_config.hpp>
#include <srs_app_st.hpp>
#include <srs_app_utility.hpp>
#include <srs_core_performance.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_protocol_utility.hpp>
#include <srs_protocol_json.hpp>

SrsMarsConn::SrsMarsConn(SrsServer* svr, st_netfd_t c, string cip)
: SrsConnection(svr, c, cip)
{
    server = svr;
    
    //rtmp = new SrsRtmpServer(skt);
    kbps = new SrsKbps();
    kbps->set_io(skt, skt);
}

SrsMarsConn::~SrsMarsConn()
{
   // srs_freep(rtmp);
    srs_freep(kbps);
}

void SrsMarsConn::dispose()
{
    SrsConnection::dispose();
}

// TODO: return detail message when error for client.
int SrsMarsConn::do_cycle()
{
    int ret = ERROR_SUCCESS;
    
    srs_trace("MARS client ip=%s, fd=%d", ip.c_str(), st_netfd_fileno(stfd));

    /*rtmp->set_recv_timeout(SRS_CONSTS_MARS_TMMS);
    rtmp->set_send_timeout(SRS_CONSTS_MARS_TMMS);
    
    if ((ret = rtmp->handshake()) != ERROR_SUCCESS) {
        srs_error("mars handshake failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("mars handshake success");
    
    SrsRequest* req = info->req;
    if ((ret = rtmp->connect_app(req)) != ERROR_SUCCESS) {
        srs_error("rtmp connect vhost/app failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("rtmp connect app success");
    
    // set client ip to request.
    req->ip = ip;
    
    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost(req->vhost);
    if (parsed_vhost) {
        req->vhost = parsed_vhost->arg0();
    }
    
    srs_info("discovery app success. schema=%s, vhost=%s, port=%d, app=%s",
             req->schema.c_str(), req->vhost.c_str(), req->port, req->app.c_str());
    
    if (req->schema.empty() || req->vhost.empty() || req->port == 0 || req->app.empty()) {
        ret = ERROR_RTMP_REQ_TCURL;
        srs_error("discovery tcUrl failed. "
                  "tcUrl=%s, schema=%s, vhost=%s, port=%d, app=%s, ret=%d",
                  req->tcUrl.c_str(), req->schema.c_str(), req->vhost.c_str(), req->port, req->app.c_str(), ret);
        return ret;
    }
    
    // check vhost, allow default vhost.
    if ((ret = check_vhost(true)) != ERROR_SUCCESS) {
        srs_error("check vhost failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("check vhost success.");
    
    srs_trace("connect app, "
              "tcUrl=%s, pageUrl=%s, swfUrl=%s, schema=%s, vhost=%s, port=%d, app=%s, args=%s",
              req->tcUrl.c_str(), req->pageUrl.c_str(), req->swfUrl.c_str(),
              req->schema.c_str(), req->vhost.c_str(), req->port,
              req->app.c_str(), (req->args? "(obj)":"null"));
    
    // show client identity
    if(req->args) {
        std::string srs_version;
        std::string srs_server_ip;
        int srs_pid = 0;
        int srs_id = 0;
        
        SrsAmf0Any* prop = NULL;
        if ((prop = req->args->ensure_property_string("srs_version")) != NULL) {
            srs_version = prop->to_str();
        }
        if ((prop = req->args->ensure_property_string("srs_server_ip")) != NULL) {
            srs_server_ip = prop->to_str();
        }
        if ((prop = req->args->ensure_property_number("srs_pid")) != NULL) {
            srs_pid = (int)prop->to_number();
        }
        if ((prop = req->args->ensure_property_number("srs_id")) != NULL) {
            srs_id = (int)prop->to_number();
        }
        
        srs_info("edge-srs ip=%s, version=%s, pid=%d, id=%d",
                 srs_server_ip.c_str(), srs_version.c_str(), srs_pid, srs_id);
        if (srs_pid > 0) {
            srs_trace("edge-srs ip=%s, version=%s, pid=%d, id=%d",
                      srs_server_ip.c_str(), srs_version.c_str(), srs_pid, srs_id);
        }
    }
    
    ret = service_cycle();
    
    int disc_ret = ERROR_SUCCESS;
    if ((disc_ret = on_disconnect()) != ERROR_SUCCESS) {
        srs_warn("connection on disconnect peer failed, but ignore this error. disc_ret=%d, ret=%d", disc_ret, ret);
    }*/
    
    return ret;
}

void SrsMarsConn::resample()
{
    kbps->resample();
}

int64_t SrsMarsConn::get_send_bytes_delta()
{
    return kbps->get_send_bytes_delta();
}

int64_t SrsMarsConn::get_recv_bytes_delta()
{
    return kbps->get_recv_bytes_delta();
}

void SrsMarsConn::cleanup()
{
    kbps->cleanup();
}

int SrsMarsConn::service_cycle()
{
    int ret = ERROR_SUCCESS;

    return ret;
}