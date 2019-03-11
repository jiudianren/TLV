/*
 * main.cpp
 *
 *  Created on: 2019年1月10日
 *      Author: lian.pengfei
 */


#include "RspCommon/log.h"
#include "RspCommon/RspTlv.h"
#include "RspCommon/RspTlv.h"
#include "RspCommon/TriggerTlv.h"
#include <iostream>


void  TestRspTlv()
{
    size_t  len_10 = 10;
    uint8_t * val_127 = new uint8_t [len_10] { 0x01,2,3,4,5,6,7,8,9,0};

    size_t  len_130 = 130;
    uint8_t * val_130 = new uint8_t [len_130] {
        1,2,3,4,5,6,7,8,9,0 ,
        2,2,3,4,5,6,7,8,9,0 ,
        3,2,3,4,5,6,7,8,9,0 ,
        4,2,3,4,5,6,7,8,9,0 ,
        5,2,3,4,5,6,7,8,9,0 ,
        6,2,3,4,5,6,7,8,9,0 ,
        7,2,3,4,5,6,7,8,9,0 ,
        8,2,3,4,5,6,7,8,9,0 ,
        9,2,3,4,5,6,7,8,9,0 ,
        0,2,3,4,5,6,7,8,9,0 ,
        1,2,3,4,5,6,7,8,9,0 ,
        2,2,3,4,5,6,7,8,9,0 ,
        3,2,3,4,5,6,7,8,9,0 ,
    };

    size_t  len_260 = 260;
    uint8_t * val_260 = new uint8_t [len_260]() ;
    val_260[0]= 0x09;
    val_260[259]= 0x09;


    RspTlv tlv10( 10, len_10, val_127);
    RspTlv tlv11( 11, len_130, val_130);
    RspTlv tlv12( 12, len_260, val_260);

    auto encode = tlv10.encode();
    encode = tlv11.encode();
    encode = tlv12.encode();

    LOG_TRACE << "decode:======= ";
    LOG_TRACE << std::endl;
    RspTlv tlv;
    tlv.clear();

    encode = tlv10.encode();
    if( tlv.decode( encode.first.get(), encode.second))
    {
        tlv.encode();
        LOG_TRACE <<" test  decode result:" <<std::endl;
    }

    encode = tlv11.encode();
    const uint8_t *  in = encode.first.get();
    size_t   in_len= encode.second;
    LOG_TRACE << octet_to_hex()(in ,in_len) ;
    tlv.clear();


    if( tlv.decode( in,  in_len ))
    {
        LOG_TRACE <<" test result:" <<std::endl;
        tlv.encode();
    }

    encode = tlv12.encode();
    if( tlv.decode( encode.first.get(), encode.second))
    {
        tlv.encode();
    }

}


void TestSMSTriggerTlv()
{
    LOG_TRACE_START;
    LOG_TRACE <<"\n \n";

    std::string sAgentId("X-Admin-From");
    std::string post_header("I am header");

    /* 两层： */
    HttpPostPara  tlv_httpPost;
    tlv_httpPost.m_tAgentId.setLenAndVal(sAgentId.length(), (unsigned char *)sAgentId.c_str());
    tlv_httpPost.m_tAdminHost.setLenAndVal(post_header.length(), (uint8_t * )post_header.c_str());

    auto encodeRes =   tlv_httpPost.encode();
    LOG_DEBUG<< " Result: len [" <<encodeRes.second <<"] "
            << "value:["<<  octet_to_hex()( encodeRes.first.get() , encodeRes.second) << "]" ;


    LOG_TRACE << "decode:======= ";
    HttpPostPara  tlv_TestHttpPostPara;
    tlv_TestHttpPostPara.decode( encodeRes.first.get(), encodeRes.second );


    auto decodeRes =  tlv_TestHttpPostPara.encode();
    LOG_DEBUG<< " Result: len [" <<decodeRes.second <<"] "
            << "value:["<<  octet_to_hex()( decodeRes.first.get() , decodeRes.second) << "]" ;

    decodeRes =  tlv_TestHttpPostPara.m_tAdminHost.encode();
    LOG_DEBUG<< " AdminHost Result: len [" <<decodeRes.second <<"] "
            << "value:["<<  octet_to_hex()( decodeRes.first.get() , decodeRes.second) << "]" ;

    decodeRes =  tlv_TestHttpPostPara.m_tAgentId.encode();
    LOG_DEBUG<< " Agent Id Result: len [" <<decodeRes.second <<"] "
            << "value:["<<  octet_to_hex()( decodeRes.first.get() , decodeRes.second) << "]" ;



    /*三层*/
    LOG_TRACE <<"\n \n";

    SecurityDomain tlv_AdmSessTrigger;

    tlv_AdmSessTrigger.m_tHttpPostPara.m_tAdminHost.setLenAndVal(post_header.length(), (uint8_t * )post_header.c_str());
    tlv_AdmSessTrigger.m_tHttpPostPara.m_tAgentId.setLenAndVal( sAgentId.length(), (uint8_t *)sAgentId.c_str());

    std::string sRetryPolicy("retry policy");
    tlv_AdmSessTrigger.m_tRetryPolicy.setLenAndVal(sRetryPolicy.length(), (uint8_t * )sRetryPolicy.c_str());

    encodeRes =  tlv_AdmSessTrigger.encode();

    LOG_DEBUG<< " Result: len [" <<encodeRes.second <<"] "
            << "value:["<<  octet_to_hex()( encodeRes.first.get() , encodeRes.second) << "]" ;

    LOG_TRACE << "decode:======= ";
    SecurityDomain tlv_decodeAdmSessTrigger;
    tlv_decodeAdmSessTrigger.decode( encodeRes.first.get(), encodeRes.second );

    encodeRes =  tlv_decodeAdmSessTrigger.encode();
    LOG_DEBUG<< " Result: len [" <<encodeRes.second <<"] "
            << "value:["<<  octet_to_hex()( encodeRes.first.get() , encodeRes.second) << "]" ;


    LOG_TRACE_END;
    LOG_TRACE <<"\n \n";

}
int main()
{

    bool   console = true;
    auto  level = boost::log::trivial::trace;
    pid_t pid = getpid();
    std::string path = std::string(getenv("RSP_ROOT_DIR")) + "/Simulator/log/eUICC/";
    std::string name = std::string("test_tlv_") + std::to_string(pid) + "_%N.log";


    LOG_TRACE<< "log path:" <<path;
    LOG_TRACE<< "log file name :" <<name;

    if (init_logging(path, name, console, level) == false)
    {
        std::cerr << "init_logging of eUICCSim_ failed" << std::endl;
        return -1;
    }



    TestRspTlv();
    TestSMSTriggerTlv();
}

