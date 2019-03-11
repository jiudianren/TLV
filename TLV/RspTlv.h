/*
 * TLV.h
 *
 *  Created on: 2019年1月10日
 *      Author: lian.pengfei
 */

#ifndef RSPTLV_H_
#define RSPTLV_H_

#include <stdint.h>
#include <stddef.h>
#include <algorithm>
#include <memory>
#include <map>
#include <netinet/in.h>

#include "log.h"
#include "zUtility/ZteUtility.h"

//使用编译选项控制
#define  RSP_TLV_DEBUG

//todo 优化方向
/*
 * RSPTlv目前，存在 频繁申请内存的情况，
 * 频繁申请小块内存，会造成内存碎片，并且影响性能

 *
 * 每个tlv 预申请 一定大小的内存,用于存放 val
 * 当其val实际带下小于 预设置大小时，使用lengt_标识其实际使用大小。
 * 当val超出 预设置大小时，重新申请大小。
 * */
#define  TLV_MAX_VAL_LENGTH 1000

class RspTlv
{
public:
    enum TLVTYPE
    {
        BERTLV ,
        COMPACTTLV ,
        COMPREHENSIONTLV  ,
    };

    RspTlv():tag_(0), length_(0), value_(nullptr){ }

    RspTlv(uint8_t tag):
        tag_(tag), length_(0), value_(nullptr) {}

    RspTlv(uint8_t tag, size_t length,uint8_t * value):
        tag_(tag), length_(length), value_(build_value( length, value)) {}

    /// @param tlv The TLV to copy from.
    RspTlv(const RspTlv& tlv) :tag_(tlv.tag_),length_(tlv.length_),
        value_(build_value(tlv.length_, tlv.value_)){}


    virtual ~RspTlv() {
        if( value_ != nullptr)
        {
            delete [] value_;
        }
    }
    RspTlv& operator=(const RspTlv& rhs);
    operator bool();


public:
    std::pair<std::unique_ptr<uint8_t[]>, size_t>  virtual encode();
    bool virtual decode (const uint8_t * in, size_t &  in_len );
    bool virtual decode (std::pair<std::unique_ptr<uint8_t[]>, size_t> inPair );
    void  virtual clear();
    size_t getEncodeLen();

public:
    uint8_t & tag()  { return tag_; }
    const uint8_t  tag() const { return tag_; }
    virtual size_t   getLength()  {return length_; }
    virtual  uint8_t * getValue()  { return value_; }
    void setValue(const uint8_t * in,  size_t  in_len ) ;
    void setTag(uint8_t  tag){ tag_ = tag;}
    void setLength(size_t len);
    void setLenAndVal( size_t len, uint8_t * value );

protected:
    bool decodeVal(const uint8_t * in, size_t  in_len);
    bool decodeTag(const uint8_t* in, uint8_t & tlv_tag, size_t & out_len );
    bool decodeLen(const uint8_t * in, size_t & tlv_len, size_t & out_len);

    virtual bool  decodeSubVal( const uint8_t * in,  size_t  in_len ){ return true; }

protected:
    void encodeTag(uint8_t* out) const;
    void encodeLen(uint8_t* out) ;
    void encodeVal(uint8_t* out);

protected:
    size_t val_length()  { return   getLength()  ;}
    size_t tag_length() const{ return 1;}
    size_t len_length();
    size_t len_length(size_t val_len);

    bool check_tag(const uint8_t  & ctag ) const;
    bool check_tag( uint8_t  & ctag );

protected:
    uint8_t* build_value(const size_t & l, uint8_t * v) {
        uint8_t * t(new uint8_t[l]);
        std::copy(v, v+l, t);
        return t;
    }


protected:
    uint8_t     tag_;
    uint8_t *   value_;
    size_t      length_; //value_ 的长度
};

#endif /* SIMULATOR_TLVTEST_RSPTLV_H_ */
