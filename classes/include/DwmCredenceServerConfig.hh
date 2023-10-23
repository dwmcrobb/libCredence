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
//!  \file DwmCredenceServerConfig.hh
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCESERVERCONFIG_HH_
#define _DWMCREDENCESERVERCONFIG_HH_

#include <set>
#include <boost/asio.hpp>

#include "DwmIpPrefix.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    class ServerConfig
    {
    public:
      bool ParseString(const std::string & configString);
      
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      const std::set<boost::asio::ip::tcp::endpoint> & Addresses() const;
      
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      const std::set<boost::asio::ip::tcp::endpoint> &
      Addresses(const std::set<boost::asio::ip::tcp::endpoint> & addrs);

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      void AddAddress(const boost::asio::ip::tcp::endpoint & addr);

      //----------------------------------------------------------------------
      //!  Returns the directory where our private key, public key and known
      //!  client keys are stored.
      //----------------------------------------------------------------------
      const std::string & KeyDirectory() const;
      
      //----------------------------------------------------------------------
      //!  Sets and returns the directory where our private key, public key
      //!  and known client keys are stored.
      //----------------------------------------------------------------------
      const std::string & KeyDirectory(const std::string & keyDir);

      //----------------------------------------------------------------------
      //!
      //----------------------------------------------------------------------
      const std::set<IpPrefix> & AllowedClients() const;

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      std::set<IpPrefix> & AllowedClients();

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      void Clear();

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      friend std::ostream &
      operator << (std::ostream & os, const ServerConfig & cfg);
      
    private:
      std::set<boost::asio::ip::tcp::endpoint>  _serverAddresses;
      std::string                               _keyDirectory;
      std::set<IpPrefix>                        _allowedClients;
    };
    
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCESERVERCONFIG_HH_
