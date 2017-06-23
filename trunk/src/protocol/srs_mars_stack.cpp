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

#include <srs_mars_stack.hpp>
#include <srs_protocol_io.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_core_autofree.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_mars_consts.h>
// for srs-librtmp, @see https://github.com/ossrs/srs/issues/213
#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdlib.h>
using namespace std;

#define MAX_PACKET_LEN (4096)

SrsInputStream::SrsInputStream(ISrsProtocolReaderWriter* skt) {
    io = skt;
    buf = new SrsBuffer();
    recycle_buf = NULL;
}

SrsInputStream::~SrsInputStream() {
    srs_freep(buf);
    srs_freep(recycle_buf);
}

int8_t SrsInputStream::read_1bytes() {
// todo 
    return 0;
}

int16_t SrsInputStream::read_2bytes(){
   // todo 
    return 0; 
}

int32_t SrsInputStream::read_4bytes(){
    srs_assert(makeSureDataAvail(4) == ERROR_SUCCESS);
    return buf->read_4bytes();
}

std::string SrsInputStream::read_string(int len){
    srs_assert(makeSureDataAvail(len) == ERROR_SUCCESS);
    return buf->read_string(len);
}

int SrsInputStream::makeSureDataAvail(int minimallen) {

    if (false == buf->is_data_avail(minimallen)) {
        int need_buf_len = MAX_PACKET_LEN;
        if (minimallen > need_buf_len)
            need_buf_len = minimallen;
        char* tmp_buf = new char[need_buf_len];
        memset(tmp_buf,0,need_buf_len);

        ssize_t nread = 0;
        if ( io->read(tmp_buf, need_buf_len, &nread) != ERROR_SUCCESS)  {
            return ERROR_SOCKET_READ;
        }

        if (nread < minimallen) {
            ssize_t nread2 = 0;
            if ( io->read_fully(tmp_buf+nread, minimallen-nread, &nread2) != ERROR_SUCCESS)  {
                return ERROR_SOCKET_READ;
            }
            srs_assert((minimallen-nread) == nread2 );
            nread += nread2;
        }
        srs_assert(buf->append(tmp_buf,nread) == ERROR_SUCCESS);
        recycle_buf = buf->data();
    }
    return ERROR_SUCCESS;
}

SrsMarsDemoEncapsulation::SrsMarsDemoEncapsulation(SrsInputStream* is,ISrsProtocolReaderWriter* skt) {
    input_stream = is;
    io = skt;
}

int SrsMarsDemoEncapsulation::dump_msg(SrsMarsMsg *msg)
{
    int ret = ERROR_SUCCESS;

    SrsBuffer *buf = new SrsBuffer();

    int pkt_total_len = msg->msg_hdr->len();
    if (msg->msg_body != NULL) {
        pkt_total_len += msg->msg_body->size();
    }

    char *buf_mem = new char[pkt_total_len];
    memset(buf_mem, 0, pkt_total_len);

    ret = buf->initialize(buf_mem, pkt_total_len);
    if (ret == ERROR_SUCCESS)
    {
        encode_pkt_hdr(msg->msg_hdr, buf);
        encode_pkt_body(msg->msg_body, buf);

        int pkt_total_len_coded = buf->pos();
        ssize_t nwrite = 0;
        ret = io->write(buf->data(), pkt_total_len_coded, &nwrite);

        if (nwrite != pkt_total_len_coded)
        {
            srs_warn("dump_msg error because io->write");
            ret = ERROR_SOCKET_WRITE;
        }
    }

    srs_freepa(buf_mem);
    srs_freep(buf);
    return ret;
}

SrsMarsPktHdr* 	SrsMarsDemoEncapsulation::decode_pkt_hdr() {
    
    int ret = input_stream->makeSureDataAvail(20);
    if (ret != ERROR_SUCCESS)
        return NULL;
    
    SrsMarsPktHdr* pkt_hdr = new SrsMarsPktHdr();

    int32_t headLength = input_stream->read_4bytes();
    srs_info("headLength = %d",headLength);
    pkt_hdr->headLength = headLength;

    int32_t clientVersion = input_stream->read_4bytes();
    srs_info("clientVersion = %d",clientVersion);
    pkt_hdr->clientVersion = clientVersion;

    int32_t cmdId = input_stream->read_4bytes();
    srs_trace("cmdId = %d",cmdId);
    pkt_hdr->cmdId = cmdId;

    int32_t seq = input_stream->read_4bytes();
    srs_trace("seq = %d",seq);
    pkt_hdr->seq = seq;

    int32_t bodyLen = input_stream->read_4bytes();
    srs_trace("bodyLen = %d",bodyLen);
    pkt_hdr->bodyLen = bodyLen;

    return pkt_hdr;
}

SrsBuffer* 		SrsMarsDemoEncapsulation::decode_pkt_body(int bodyLen) {
    if (bodyLen <= 0) {
        return NULL;
    }

    SrsBuffer* buf = new SrsBuffer();
    char* buf_body = new char[bodyLen];
    memset(buf_body, 0, bodyLen);

    ssize_t nread = 0;
    if ( io->read_fully(buf_body, (size_t)bodyLen, &nread) == ERROR_SUCCESS && nread == bodyLen ) {
        buf->initialize(buf_body, nread);
        return buf;
    } else {
        srs_freep(buf_body);
        srs_freep(buf);
    }
    return NULL;
}

int SrsMarsDemoEncapsulation::encode_pkt_hdr(SrsMarsPktHdr* pPktHdr, SrsBuffer* buf) {
    int ret = ERROR_SUCCESS;

    buf->write_4bytes(pPktHdr->headLength);
    buf->write_4bytes(pPktHdr->clientVersion);
    buf->write_4bytes(pPktHdr->cmdId);
    buf->write_4bytes(pPktHdr->seq);
    buf->write_4bytes(pPktHdr->bodyLen);

    return ret;
}

int SrsMarsDemoEncapsulation::encode_pkt_body(SrsBuffer *pPkgBody, SrsBuffer *buf)
{
    int ret = ERROR_SUCCESS;
    if (pPkgBody != NULL && buf != NULL)
    {
        buf->write_bytes(pPkgBody->data(), pPkgBody->size());
    }

    return ret;
}

SrsMarsMsg::SrsMarsMsg(ISrsMarsEncapsulation* encapsulation) {
    msg_encapsulation = encapsulation;
    msg_hdr = NULL;
    msg_body = NULL;
}

void SrsMarsMsg::dispose() {
    srs_freep(msg_hdr);
    char* msg_body_buf = msg_body->data();
    srs_freepa(msg_body_buf);
    srs_freep(msg_body);
}

int SrsMarsMsg::pull()
{
    int ret = ERROR_SUCCESS;

    assert(msg_encapsulation != NULL);
    msg_hdr = msg_encapsulation->decode_pkt_hdr();
    if (NULL == msg_hdr)
    {
        ret = ERROR_UNPACK_PKT_HDR;
    }
    else
    {
        if (msg_hdr->bodyLen > 0)
        {
            msg_body = msg_encapsulation->decode_pkt_body(msg_hdr->bodyLen);
            if (NULL == msg_body)
            {
                ret = ERROR_UNPACK_PKT_BODY;
            }
        }
    }
    return ret;
}

int SrsMarsMsg::push() {
    int ret = ERROR_SUCCESS;

    assert(msg_encapsulation != NULL); 
    ret = msg_encapsulation->dump_msg(this);

    return ret;
}

SrsMarsServer::SrsMarsServer(ISrsProtocolReaderWriter* skt)
{
    io = skt;
    input_stream = new SrsInputStream(skt);
    msg_encapsulation = new SrsMarsDemoEncapsulation(input_stream, io);
    //protocol = new SrsProtocol(skt);
   // hs_bytes = new SrsHandshakeBytes();
}

int  SrsMarsServer::test_recv()
{
    int ret = ERROR_SUCCESS;
    ret = input_stream->makeSureDataAvail(20);
    if (ret != ERROR_SUCCESS)
        return ret;
    
    int32_t headLength = input_stream->read_4bytes();
    srs_trace("headLength = %d",headLength);

    int32_t clientVersion = input_stream->read_4bytes();
    srs_trace("clientVersion = %d",clientVersion);


    int32_t cmdId = input_stream->read_4bytes();
    srs_trace("cmdId = %d",cmdId);

    int32_t seq = input_stream->read_4bytes();
    srs_trace("seq = %d",seq);

    int32_t bodyLen = input_stream->read_4bytes();
    srs_trace("bodyLen = %d",bodyLen);

    return ret;
}

int SrsMarsServer::service_impl() {
    int ret = ERROR_SUCCESS;

    SrsMarsMsg* mars_msg = new SrsMarsMsg(msg_encapsulation);

    // 从网络拉取消息
    ret = mars_msg->pull();
    if (ret == ERROR_SUCCESS) {
        // handle the mars_msg
        if (mars_msg->msg_hdr->cmdId == SRS_MARS_CMD_HEARTBEAT) {
            srs_info("i receive heartbeat pkt");
            //消息从网络发出
            ret = mars_msg->push();
            srs_info("i reply heartbeat pkt");
        }
        else {
            srs_info("i receive pkt (%d)",mars_msg->msg_hdr->cmdId );
        }
    }
    srs_freep(mars_msg);
    return ret;
}
