#ifndef _TRIGGERTLV_H_
#define _TRIGGERTLV_H_

#include "RspTlv.h"

class AdminHost : public  RspTlv
{
public:
    AdminHost():RspTlv(0x8A){}
};


/*X-Admin-From*/
class AgentId : public  RspTlv
{
public:
    AgentId():RspTlv(0x8B){}
};



class HttpPostPara : public RspTlv
{
public:
    HttpPostPara():RspTlv(0x89){}
    AdminHost  m_tAdminHost;
    AgentId  m_tAgentId;

    size_t getLength()  override;
    uint8_t * getValue()  override;

    bool decodeSubVal(const uint8_t * in,  size_t  in_len) override;
};


class ConnectPara :public RspTlv
{
public:
    ConnectPara():RspTlv(0x84){}

};


class RetryPolicy :public RspTlv
{
public:
    RetryPolicy():RspTlv(0x85){}
};


//Security Domain parameters value
class SecurityDomain :public RspTlv
{
public:
    SecurityDomain():RspTlv(0x83){}

    HttpPostPara  m_tHttpPostPara;
    RetryPolicy   m_tRetryPolicy;

    size_t getLength()  override;
    uint8_t * getValue()  override;
    bool decodeSubVal(const uint8_t * in,  size_t  in_len) override;
};


//Administration session triggering
class AdminSessTrigger : public RspTlv
{
public:
    AdminSessTrigger():RspTlv(0x81){}

    SecurityDomain  m_tSecurityDomain;

    size_t getLength()  override;
    uint8_t * getValue()  override;
    bool decodeSubVal(const uint8_t * in,  size_t  in_len) override;
};

#endif
