/*
 * TriggerTlv.cpp
 *
 *  Created on: 2019年2月20日
 *      Author: lian.pengfei
 */


#include "TriggerTlv.h"


/**
 * HttpPostPara
 */

size_t HttpPostPara::getLength()
{
    length_ = 0;
    if( m_tAdminHost )
    {
        length_ += m_tAdminHost.getEncodeLen();
    }
    if( m_tAgentId)
    {
        length_  += m_tAgentId.getEncodeLen();
    }
    return length_;
}



//不断申请内存，容易造成内存碎片化
uint8_t * HttpPostPara::getValue()  {

    if( value_ != nullptr )
    {
        delete [] value_;
    }

    auto  len = getLength();
    if( len == 0)
    {
        value_ = nullptr;
        return  value_;
    }
    uint8_t *  varValue = value_ = new uint8_t [len];

    if( m_tAdminHost)
    {
        auto encodeRes = m_tAdminHost.encode();
        memcpy(varValue, std::get<0>( encodeRes ).get(),  std::get<1>( encodeRes ));
        varValue += std::get<1>( encodeRes );
    }

    if( m_tAgentId)
    {
        auto encodeRes = m_tAgentId.encode();
        memcpy(varValue, std::get<0>( encodeRes ).get(),  std::get<1>( encodeRes ));
        varValue += std::get<1>( encodeRes );
    }

    return value_;
}

bool HttpPostPara::decodeSubVal(const uint8_t * in,  size_t  in_len)
{
    if( in_len  <  2) //tag+len 的长度至少为2
    {
        return true;
    }

    bool bflag = true;
    uint8_t tag  = 0x00;
    size_t tag_len = 0;
    bflag = decodeTag(in, tag, tag_len);

    if( tag == m_tAdminHost.tag()  )
    {
        if( !m_tAdminHost.decode(in, in_len ))
        {
            return false;
        }
        int add_len =  m_tAdminHost.getEncodeLen();
        return  decodeSubVal(in + add_len,  in_len - add_len);
    }
    else if( tag == m_tAgentId.tag()  )
    {
        if( ! m_tAgentId.decode(in, in_len))
        {
            return false;
        }
        int add_len =  m_tAgentId.getEncodeLen();
        return  decodeSubVal(in + add_len,  in_len - add_len);
    }
    else
    {
        //如果都不符合，说明是有多余长度
        return true;
    }
}


/**
 * SecurityDomain
 *
 */


size_t SecurityDomain::getLength()
{
    length_ = 0;

    if( m_tHttpPostPara )
    {
        length_ += m_tHttpPostPara.getEncodeLen();
    }
    if( m_tRetryPolicy)
    {
        length_  += m_tRetryPolicy.getEncodeLen();
    }
    return length_;
}

//不断申请内存，容易造成内存碎片化
uint8_t * SecurityDomain::getValue()  {

    if( value_ != nullptr )
    {
        delete [] value_;
    }

    auto  len = getLength();
    if( len == 0)
    {
        value_ = nullptr;
        return  value_;
    }
    uint8_t *  varValue = value_ = new uint8_t [len];

    if( m_tHttpPostPara)
    {
        auto encodeRes = m_tHttpPostPara.encode();
        memcpy(varValue, std::get<0>( encodeRes ).get(),  std::get<1>( encodeRes ));
        varValue += std::get<1>( encodeRes );
    }

    if( m_tRetryPolicy)
    {
        auto encodeRes = m_tRetryPolicy.encode();
        memcpy(varValue, std::get<0>( encodeRes ).get(),  std::get<1>( encodeRes ));
        varValue += std::get<1>( encodeRes );
    }

    return value_;
}

bool SecurityDomain::decodeSubVal(const uint8_t * in,  size_t  in_len)
{
    if( in_len  <  2) //tag+len 的长度至少为2
    {
        return true;
    }

    bool bflag = true;
    uint8_t tag  = 0x00;
    size_t tag_len = 0;
    bflag = decodeTag(in, tag, tag_len);

    if( tag == m_tHttpPostPara.tag() )
    {
        if( !m_tHttpPostPara.decode(in, in_len ))
        {
            return false;
        }
        int add_len =  m_tHttpPostPara.getEncodeLen();
        return  decodeSubVal(in + add_len,  in_len - add_len);
    }
    else if( tag == m_tRetryPolicy.tag() )
    {
        if( ! m_tRetryPolicy.decode(in, in_len))
        {
            return false;
        }
        int add_len =  m_tRetryPolicy.getEncodeLen();
        return  decodeSubVal(in + add_len,  in_len - add_len);
    }
    else
    {
        //如果都不符合，说明是有多余长度
        return true;
    }
}



/**
 * AdminSessTrigger
 *
 */

size_t AdminSessTrigger::getLength()
{
    length_ = 0;
    if( m_tSecurityDomain )
    {
        length_ += m_tSecurityDomain.getEncodeLen();
    }
    return length_;
}



//不断申请内存，容易造成内存碎片化
uint8_t * AdminSessTrigger::getValue()  {

    if( value_ != nullptr )
    {
        delete [] value_;
    }

    auto  len = getLength();
    if( len == 0)
    {
        value_ = nullptr;
        return  value_;
    }
    uint8_t *  varValue = value_ = new uint8_t [len];

    if( m_tSecurityDomain)
    {
        auto encodeRes = m_tSecurityDomain.encode();
        memcpy(varValue, std::get<0>( encodeRes ).get(),  std::get<1>( encodeRes ));
        varValue += std::get<1>( encodeRes );
    }

    return value_;
}

bool AdminSessTrigger::decodeSubVal(const uint8_t * in,  size_t  in_len)
{
    if( in_len < 2) //tag+len 的长度至少为2
    {
        return true;
    }

    bool bflag = true;
    uint8_t tag  = 0x00;
    size_t tag_len = 0;
    bflag = decodeTag(in, tag, tag_len);

    if( tag == m_tSecurityDomain.tag()  )
    {
        if( !m_tSecurityDomain.decode(in, in_len ))
        {
            return false;
        }
        int add_len =  m_tSecurityDomain.getEncodeLen();
        return  decodeSubVal(in + add_len,  in_len - add_len);
    }
    else
    {
        //如果都不符合，说明是有多余长度
        return true;
    }
}

