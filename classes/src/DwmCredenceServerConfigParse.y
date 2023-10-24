%code requires
{
  #include <string>
  #include <vector>
  #include <boost/asio.hpp>

  #include "DwmIpPrefix.hh"

  using std::vector, std::set, std::string, std::pair,
      Dwm::Ipv4Address, Dwm::Ipv4Prefix, Dwm::Ipv6Address;

  extern "C" {
    extern int credenceservercfglex_destroy(void);
  }

  typedef struct yy_buffer_state * YY_BUFFER_STATE;
  extern YY_BUFFER_STATE credenceservercfg_scan_bytes(const char *, size_t);
  extern void credenceservercfg_switch_to_buffer(YY_BUFFER_STATE buffer);

}

%{
  #include <cstdio>

  extern "C" {
    #include <netdb.h>

    extern void credenceservercfgerror(const char *arg, ...);
    extern FILE *credenceservercfgin;
  }
        
  #include <string>
  #include <vector>

  #include "DwmSvnTag.hh"
  #include "DwmSysLogger.hh"
  #include "DwmCredenceServerConfig.hh"

  using namespace std;
  
  string                               g_configPath;
  static Dwm::Credence::ServerConfig  *sg_credenceServerConfig = nullptr;
  static std::mutex                    sg_credenceServerCfgMtx;
%}

%define api.prefix {credenceservercfg}

%union {
  int                                            intVal;
  string                                        *stringVal;
  vector<string>                                *stringVecVal;
  set<Dwm::IpPrefix>                            *ipPrefixSetVal;
  Dwm::Credence::ServerConfig                   *serviceConfigVal;
  boost::asio::ip::tcp::endpoint                *serviceAddrVal;
  std::set<boost::asio::ip::tcp::endpoint>      *serviceAddrSetVal;
}

%code provides
{
  // Tell Flex the expected prototype of yylex.
  #define YY_DECL                             \
    int credenceservercfglex ()

  // Declare the scanner.
  YY_DECL;
}

%token ADDRESS ADDRESSES ALLOWEDCLIENTS KEYDIRECTORY PORT SERVICE

%token<stringVal>  STRING
%token<intVal>     INTEGER

%type<intVal>                  TCP4Port
%type<stringVal>               KeyDirectory
%type<stringVecVal>            VectorOfString
%type<serviceConfigVal>        ServiceSettings
%type<serviceAddrSetVal>       ServiceAddresses ServiceAddressSet
%type<ipPrefixSetVal>          AllowedClients
%type<serviceAddrVal>          ServiceAddress

%%

Config: Service;

Service: SERVICE '{' ServiceSettings '}' ';'
{
  if (sg_credenceServerConfig) {
      *sg_credenceServerConfig = *$3;
  }
  delete $3;
};

ServiceSettings: ServiceAddresses
{
  $$ = new Dwm::Credence::ServerConfig();
  $$->Addresses(*$1);
  delete $1;
}
| KeyDirectory
{
  $$ = new Dwm::Credence::ServerConfig();
  $$->KeyDirectory(*$1);
  delete $1;
}
| AllowedClients
{
  $$ = new Dwm::Credence::ServerConfig();
  $$->AllowedClients() = *$1;
  delete $1;
}
| ServiceSettings ServiceAddresses
{
  $$->Addresses(*$2);
  delete $2;
}
| ServiceSettings KeyDirectory
{
  $$->KeyDirectory(*$2);
  delete $2;
}
| ServiceSettings AllowedClients
{
  $$->AllowedClients() = *$2;
  delete $2;
};

ServiceAddresses: ADDRESSES '=' '[' ServiceAddressSet ']' ';'
{
    $$ = $4;
};

ServiceAddressSet: ServiceAddress
{
  $$ = new std::set<boost::asio::ip::tcp::endpoint>();
  $$->insert(*$1);
  delete $1;
}
| ServiceAddressSet ',' ServiceAddress
{
  $$->insert(*$3);
  delete $3;
};

ServiceAddress: '{' ADDRESS '=' STRING ';' '}'
{
  using batcp = boost::asio::ip::tcp;
  if (*$4 == "in6addr_any") {
    $$ = new batcp::endpoint(batcp::v6(), 2123);
  }
  else if (*$4 == "inaddr_any") {
    $$ = new batcp::endpoint(batcp::v4(), 2123);
  }
  else {
    boost::system::error_code  ec;
    boost::asio::ip::address  addr =
    boost::asio::ip::address::from_string(*$4, ec);
    if (ec) {
      credenceservercfgerror("invalid IP address");
      delete $4;
      return 1;
    }
    $$ = new boost::asio::ip::tcp::endpoint(addr, 2123);
  }
  delete $4;
}
| '{' ADDRESS '=' STRING ';' PORT '=' TCP4Port ';' '}'
{
  namespace baip = boost::asio::ip;
  using batcp =	boost::asio::ip::tcp;
  
  if (($8 <= 0) || ($8 > 65535)) {
    credenceservercfgerror("invalid port");
    delete $4;
    return 1;
  }

  if (*$4 == "in6addr_any") {
      $$ = new batcp::endpoint(batcp::v6(), $8);
  }
  else if (*$4 == "inaddr_any") {
      $$ = new batcp::endpoint(batcp::v4(), $8);
  }
  else {
    boost::system::error_code  ec;
    baip::address  addr = baip::address::from_string(*$4, ec);
    if (ec) {
      credenceservercfgerror("invalid IP address");
      delete $4;
      return 1;
    }
    $$ = new batcp::endpoint(addr, $8);
  }
  delete $4;
}
| '{' PORT '=' TCP4Port ';' ADDRESS '=' STRING ';' '}'
{
  namespace baip = boost::asio::ip;
  using batcp = boost::asio::ip::tcp;

  if (($4 <= 0) || ($4 > 65535)) {
    credenceservercfgerror("invalid port");
    delete $8;
    return 1;
  }
  baip::address  addr;
  if (*$8 == "in6addr_any") {
    $$ = new batcp::endpoint(batcp::v6(), $4);
  }
  else if (*$8 == "inaddr_any") {
    $$ = new batcp::endpoint(batcp::v4(), $4);
  }
  else {
    boost::system::error_code  ec;
    baip::address addr = baip::address::from_string(*$8, ec);
    if (ec) {
      credenceservercfgerror("invalid IP address");
      delete $8;
      return 1;
    }
    $$ = new batcp::endpoint(addr, $4);
  }
  delete $8;
};

KeyDirectory : KEYDIRECTORY '=' STRING ';'
{
  $$ = $3;
};

AllowedClients: ALLOWEDCLIENTS '=' '[' VectorOfString ']' ';'
{
  $$ = new std::set<Dwm::IpPrefix>();
  for (const auto & pfxstr : *$4) {
    Dwm::IpPrefix   pfx(pfxstr);
    if (pfx.Family() != AF_INET) {
      $$->insert(pfx);
    }
    else {
      if (pfx.Prefix<Ipv4Prefix>()->Network().Raw() != INADDR_NONE) {
        $$->insert(pfx);
      }
      else {
        credenceservercfgerror("invalid IP prefix");
        delete $4;
        return 1;
      }
    }
  }
  delete $4;
}
|
{};

TCP4Port: INTEGER
{
  if (($1 > 0) && ($1 < 65536)) {
    $$ = $1;
  }
  else {
    credenceservercfgerror("invalid TCP port number");
    return 1;
  }
}
| STRING
{
  auto  servEntry = getservbyname($1->c_str(), "tcp");
  if (servEntry) {
    $$ = ntohs(servEntry->s_port);
  }
  else {
      credenceservercfgerror("unknown TCP service");
      delete $1;
      return 1;
  }
  delete $1;
};

VectorOfString: STRING
{
  $$ = new vector<string>();
  $$->push_back(*$1);
  delete $1;
}
| VectorOfString ',' STRING    { $$->push_back(*$3); delete $3; }
;

%%

static const Dwm::SvnTag svntag("@(#) $DwmPath$");


namespace Dwm {

  namespace Credence {

    using namespace std;

    //-----------------------------------------------------------------------
    //!  
    //-----------------------------------------------------------------------
    bool ServerConfig::ParseString(const string & s)
    {
      bool  rc = false;

      if (! s.empty()) {
          std::lock_guard<std::mutex>  lock(sg_credenceServerCfgMtx);
          sg_credenceServerConfig = this;

          YY_BUFFER_STATE  buffer =
              credenceservercfg_scan_bytes(s.c_str(), s.size());
        credenceservercfg_switch_to_buffer(buffer);
        if (0 == credenceservercfgparse()) {
          rc = true;
        }
        credenceservercfglex_destroy();
      }
      sg_credenceServerConfig = nullptr;

      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const set<boost::asio::ip::tcp::endpoint> &
    ServerConfig::Addresses() const
    {
      return _serverAddresses;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const set<boost::asio::ip::tcp::endpoint> &
    ServerConfig::Addresses(const set<boost::asio::ip::tcp::endpoint> & addrs)
    {
      _serverAddresses = addrs;
      return _serverAddresses;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void ServerConfig::AddAddress(const boost::asio::ip::tcp::endpoint & addr)
    {
      _serverAddresses.insert(addr);
      return;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & ServerConfig::KeyDirectory() const
    {
      return _keyDirectory;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & ServerConfig::KeyDirectory(const string & keyDir)
    {
      _keyDirectory = keyDir;
      return _keyDirectory;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const set<IpPrefix> & ServerConfig::AllowedClients() const
    {
      return _allowedClients;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    set<IpPrefix> & ServerConfig::AllowedClients()
    {
      return _allowedClients;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void ServerConfig::Clear()
    {
      _serverAddresses.clear();
      _keyDirectory = "";
      _allowedClients.clear();
      return;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::ostream & operator << (std::ostream & os, const ServerConfig & cfg)
    {
      if (os) {
        os << "#============================================================================\n"
           << "#  Network service to allow authorized clients.\n"
           << "#============================================================================\n"
           << "server {\n";
        if (! cfg._serverAddresses.empty()) {
          os << "    addresses = [\n";
          auto  iter = cfg._serverAddresses.begin();
          os << "        { address = \"" << iter->address()
             << "\"; port = " << iter->port() << "; }";
          ++iter;
          for ( ; iter != cfg._serverAddresses.end(); ++iter) {
            os << ",\n        { address = \"" << iter->address()
               << "\"; port = " << iter->port() << "; }";
          }
          os << "\n    ];\n\n";
        }
        if (! cfg._keyDirectory.empty()) {
          os << "    keyDirectory = \"" << cfg._keyDirectory << "\";\n\n";
        }
        
        if (! cfg._allowedClients.empty()) {
          os << "    allowedClients = [\n";
          auto  iter = cfg._allowedClients.begin();
          os << "        \"" << *iter << "\"";
          ++iter;
          for ( ; iter != cfg._allowedClients.end(); ++iter) {
            os << ",\n        \"" << *iter << "\"";
          }
          os << "\n    ];\n";
        }
        os << "};\n";
      }
      return os;
    }
    
  }  // namespace Credence

}  // namespace Dwm
      
