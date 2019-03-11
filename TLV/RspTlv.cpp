/*
 * TLV.cpp
 *
 *  Created on: 2019年1月10日
 *      Author: lian.pengfei
 */

#include "RspTlv.h"

RspTlv::operator bool()  {

    if ( !check_tag( tag_ ))
    {
        return false;
    }
    if( getValue()== nullptr)
    {
        LOG_TRACE << "no value in this TLV";
        return false;
    }
    return true;
}

RspTlv& RspTlv::operator=(const RspTlv& rhs) {
    if(this == &rhs)
        return *this;

    if( value_ != nullptr)
    {
        delete [] value_;
    }
    tag_ = rhs.tag_;
    length_ = rhs.length_;
    value_ = build_value(rhs.length_, rhs.value_);
    return *this;
}
void RspTlv::setLength(size_t len)
{
    if( length_ == len)
    {
        return;
    }
    length_ = len;
    if(value_ != nullptr)
    {
        delete [] value_;
    }
    value_ = new uint8_t [length_];
}


void RspTlv::setLenAndVal( size_t len, uint8_t * value)
{
    if(value_ != nullptr )
    {
        delete [] value_ ;
    }
    length_ = len;
    value_ = new uint8_t [length_];
    memcpy(value_, value, len);
}

void RspTlv::clear()
{
    tag_ = 0;
    length_ = 0;
    if(value_)
    {
        delete [] value_;
        value_ = nullptr;
    }
}
bool RspTlv::decodeTag(const uint8_t* in, uint8_t & tlv_tag, size_t & out_len)
{
    uint8_t temp_tag = in[0];
    if( tlv_tag != 0  && temp_tag != tlv_tag )
    {
        LOG_ERROR <<"erro tag! tlv_tag ["<<std::hex  <<tlv_tag  << "], msg_tag [" << temp_tag <<"]." << std::dec;
        return false;
    }
    tlv_tag = temp_tag;
    out_len = 1;
    return check_tag (tlv_tag);
}


bool RspTlv::decodeVal(const uint8_t * in,   size_t  in_len)
{
    setValue( in, in_len);
    //对子结构进行 解码;
    if( !decodeSubVal(in, in_len) )
    {
        return false;
    }
    return true;
}

void RspTlv::setValue(const uint8_t * in,  size_t  in_len )
{
    if( in_len != length_ )
    {
        if( value_ != nullptr)
        {
            delete [] value_;
        }
        length_ = in_len;
        uint8_t *  value_  = new uint8_t [length_];
    }

    memcpy(value_, in,  in_len);
}

bool  RspTlv::decode(std::pair<std::unique_ptr<uint8_t[]>, size_t> inPair  ){
  return   decode( inPair.first.get(), inPair.second);
}

bool  RspTlv::decode (const uint8_t * in, size_t &  in_len ){
    bool bflag = true;

    size_t tag_len = 0;
    bflag = decodeTag(in, tag(), tag_len);

    size_t len_len = 0;
    size_t len_val  = 0;

    bflag = bflag ? decodeLen(in+tag_len, len_val, len_len): bflag;

    setLength(len_val);

    bflag = bflag ? (in_len >= tag_len+ len_len + len_val  ? true: false): bflag;
    bflag = bflag ? decodeVal(in + tag_len + len_len, len_val ): bflag;

    int tag_val = tag();

    if(!bflag)
    {
        LOG_TRACE << "Result:"<< " Failed ";
        return bflag;
    }

#ifdef RSP_TLV_DEBUG
    LOG_TRACE << "Result: Succ"
            << " Tlv:" << "{"
            <<" T:" << std::hex << tag_val << std::dec << ","  << octet_to_hex()( in, tag_len )
            <<" L:" << getLength() << "," <<octet_to_hex()( in+tag_len , tag_len );

    LOG_TRACE <<" V:" << octet_to_hex()( getValue(), getLength() )<< "," ;
    LOG_TRACE <<octet_to_hex()( in + tag_len + len_len , in_len - tag_len - len_len )
                                            << " Left:" << in_len - tag_len - len_len -len_val
                                            <<"}";
#endif

    return   bflag;
}

size_t RspTlv::len_length(size_t val_len)
{
    if ( val_len >= 65535 || val_len == 0)
    {
        LOG_ERROR << "no value or val too long  in the tlv!";
        return 0;
    }

    if ( val_len > 255)
    {
        return 3;
    }
    else if (val_len > 127)
    {
        return 2;
    }
    else
    {
        return 1;
    }
}

size_t RspTlv::len_length()
{
    auto val_len = val_length();
    return len_length( val_len);
}
bool RspTlv::check_tag( uint8_t  & ctag )
{
    /* 暂时不支持这几种tag*/
    if ( ctag == 0x00 || ctag ==0x7F || ctag ==0x80 || ctag  ==0xFF)
    {
        LOG_ERROR<< "not support this tag:[" << std::hex<< ctag << "]"<< std::dec;
        return false;
    }
    return true;
}

bool RspTlv::check_tag(const uint8_t  & ctag ) const
{
    /* 暂时不支持这几种tag*/
    if ( ctag == 0x00 || ctag ==0x7F || ctag ==0x80 || ctag  ==0xFF)
    {
        LOG_ERROR<< "not support this tag:[" << std::hex<< ctag << "]"<< std::dec;
        return false;
    }
    return true;
}

void RspTlv::encodeTag(uint8_t* out) const
{
    out[0] = (uint8_t) tag_;
}

void RspTlv::encodeVal(uint8_t* out)
{
    memcpy(out, getValue() , val_length());
}
void RspTlv::encodeLen(uint8_t* out)
{
    auto val_len =  val_length();
    size_t len_len =  len_length(val_len);
    if ( len_len == 0 )
    {
        LOG_ERROR<< " length erro!";
        return ;
    }

    if ( val_len > 255)
    {
        out[0] = 0x82;
        unsigned short Lcc_bin = htons((unsigned short) val_len );
        memcpy(out + 1, &Lcc_bin, sizeof(Lcc_bin));
    }
    else if ( val_len > 127)
    {
        out[0] = 0x81;
        out[1] = (uint8_t) length_;
    }
    else if ( val_len == 0)
    {
        LOG_ERROR << "val length is zero!";
    }
    else
    {
        out[0] = (uint8_t) val_len;
    }

}
bool RspTlv::decodeLen(const uint8_t * in, size_t & tlv_len, size_t & out_len)
{
    bool ret = true;
    switch ( in[0])
    {
        case 0x83:
        {
            ret = false;
            LOG_ERROR<< " not support now!";
            break;
        }
        case 0x82:
        {
            out_len = 3;
            uint16_t temp = 0;
            memcpy(&temp,  &in[1], sizeof(temp));
            tlv_len = ntohs(temp);
            break;
        }
        case 0x81:
        {
            out_len =  2;
            tlv_len = in[1];
            break;
        }
        default:
        {
            out_len =  1;
            tlv_len = in[0];
        }

    }
    return ret;
}

size_t RspTlv::getEncodeLen()
{
    size_t tag_len = tag_length();
    size_t val_len = val_length();
    size_t len_len = len_length(val_len);
    size_t out_len = tag_len + len_len + val_len;
    return out_len;
}

std::pair<std::unique_ptr<uint8_t[]>, size_t> RspTlv::encode()
{
    size_t tag_len = tag_length();
    size_t val_len = val_length();
    size_t len_len = len_length(val_len);

    size_t out_len = tag_len + len_len + val_len;
    std::unique_ptr<uint8_t[]> out_encoded(new uint8_t[out_len]);

    encodeTag( out_encoded.get() );
    encodeLen( out_encoded.get()+tag_len);
    encodeVal( out_encoded.get()+tag_len+len_len);

#ifdef RSP_TLV_DEBUG

    LOG_TRACE << "info:"
            << " T:"<<tag_len << "," <<"[" << octet_to_hex()( out_encoded.get() , tag_len) << "]"
            << " L:"<<len_len << "," <<"[" << octet_to_hex()( out_encoded.get()+ tag_len, len_len)<< "]"
            << " V:"<<val_len << "," <<"[" << octet_to_hex()( out_encoded.get()+tag_len+len_len , val_len)<<"]"
            << std::endl;

    LOG_TRACE<< " Result:"<<out_len << "," <<"[" << octet_to_hex()( out_encoded.get() , out_len) << "]"
            << std::endl;
#endif

    return std::make_pair(std::move(out_encoded), out_len);
}
