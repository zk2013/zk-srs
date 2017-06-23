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

#ifndef SRS_PROTOCOL_MARS_HPP
#define SRS_PROTOCOL_MARS_HPP

#include <srs_core.hpp>

// for srs-librtmp, @see https://github.com/ossrs/srs/issues/213
#ifndef _WIN32
#include <sys/uio.h>
#endif
#include <string>

#include <srs_kernel_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_consts.hpp>
#include <srs_core_performance.hpp>

class ISrsProtocolReaderWriter;
class SrsBuffer;
class SrsInputStream;
class SrsMarsMsg;

// 数据包头部基础类,可以继承此类实现加密,压缩等功能
class SrsMarsPktHdr {
public:
	SrsMarsPktHdr() {
		headLength = 0;
		clientVersion = 0;
		cmdId = -1;
		seq = -1;
		bodyLen = 0;
	}
	virtual ~SrsMarsPktHdr() { }

virtual int len() {
	return 20;
}
public:
	int headLength;
	int clientVersion;
	int cmdId;
	int seq;
	int bodyLen;
};

// 数据解包和封包,实现此接口,自定义数据包的头部,数据包的包体是否压缩,加密等.
class  ISrsMarsEncapsulation {
public:
	/**
	 * return NULL if fail.
	 */
	virtual SrsMarsPktHdr* 	decode_pkt_hdr() = 0;

	/**
	 * return NULL if fail.
	 */
	virtual SrsBuffer* 		decode_pkt_body(int bodyLen) = 0;
	/**
	 * 编解码的结果保存在SrsBuffer中
	 */
	virtual int encode_pkt_hdr(SrsMarsPktHdr* pPktHdr, SrsBuffer* buf) = 0 ;
	virtual int encode_pkt_body(SrsBuffer* pPkgBody, SrsBuffer* buf) = 0;
// 输出一个消息到网络或文件
	virtual int dump_msg(SrsMarsMsg* msg) = 0;
};

// 包含消息的网络获取解包和封包发送
class SrsMarsDemoEncapsulation : public ISrsMarsEncapsulation {
public:
	SrsMarsDemoEncapsulation(SrsInputStream* is,ISrsProtocolReaderWriter* skt);

// input_stream 用于网络获取解包,由于解包需要从网络读取特定的数据,所以封装一个SrsInputStream类
// 在 decode_pkt_hdr中用SrsInputStream读数据,不同ISrsMarsEncapsulation实现类的实现不同
	SrsInputStream* input_stream;
// 封包发送只需要一个底层io类
	ISrsProtocolReaderWriter* io;
	/**
	 * return NULL if fail.
	 */
	virtual SrsMarsPktHdr* 	decode_pkt_hdr();
	/**
	 * return NULL if fail.
	 */
	virtual SrsBuffer* 		decode_pkt_body(int bodyLen);

	virtual int encode_pkt_hdr(SrsMarsPktHdr* pPktHdr, SrsBuffer* buf)  ;
	virtual int encode_pkt_body(SrsBuffer* pPkgBody, SrsBuffer* buf) ;
	virtual int dump_msg(SrsMarsMsg* msg) ;
};

class SrsMarsMsg {
public:
	SrsMarsMsg(ISrsMarsEncapsulation* encapsulation);

// 释放消息头和消息体占用的资源
	void dispose();
// 消息头
	SrsMarsPktHdr* msg_hdr;
// 消息体
	SrsBuffer* msg_body;
//消息的封装格式
	ISrsMarsEncapsulation*  msg_encapsulation;
// 实例化此消息的内容,通过 ISrsMarsEncapsulation接口
 	int pull();
//输出此消息
	int push();
};

class SrsInputStream {
public:
	SrsInputStream(ISrsProtocolReaderWriter* skt);
	~SrsInputStream();

	virtual int8_t read_1bytes();
	virtual int16_t read_2bytes();
	virtual int32_t read_4bytes();
	virtual std::string read_string(int len);
	int makeSureDataAvail(int minimallen);
private:
	char* recycle_buf;
	SrsBuffer* buf;
	ISrsProtocolReaderWriter* io; 
};

class SrsMarsServer {
public:
    SrsMarsServer(ISrsProtocolReaderWriter* skt);
// for test
		int test_recv();
	// 服务的实现,有SrsMarsConn类循环用调
	virtual int service_impl();

private:
	SrsInputStream* input_stream;
	ISrsMarsEncapsulation*  msg_encapsulation;
 	ISrsProtocolReaderWriter* io;
};

#endif

