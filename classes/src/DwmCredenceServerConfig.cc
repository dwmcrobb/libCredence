//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//
//  1. Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//  3. The names of the authors and copyright holders may not be used to
//     endorse or promote products derived from this software without
//     specific prior written permission.
//
//  IN NO EVENT SHALL DANIEL W. MCROBB BE LIABLE TO ANY PARTY FOR
//  DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
//  INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE,
//  EVEN IF DANIEL W. MCROBB HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
//  DAMAGE.
//
//  THE SOFTWARE PROVIDED HEREIN IS ON AN "AS IS" BASIS, AND
//  DANIEL W. MCROBB HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT,
//  UPDATES, ENHANCEMENTS, OR MODIFICATIONS. DANIEL W. MCROBB MAKES NO
//  REPRESENTATIONS AND EXTENDS NO WARRANTIES OF ANY KIND, EITHER
//  IMPLIED OR EXPRESS, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE,
//  OR THAT THE USE OF THIS SOFTWARE WILL NOT INFRINGE ANY PATENT,
//  TRADEMARK OR OTHER RIGHTS.
//===========================================================================

//---------------------------------------------------------------------------
//!  \file DwmCredenceServerConfig.cc
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#include "DwmSvnTag.hh"
#include "DwmCredenceServerConfig.hh"

static const Dwm::SvnTag svntag("@(#) $DwmPath$");

namespace Dwm {

  namespace Credence {

    using namespace std;
    
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
