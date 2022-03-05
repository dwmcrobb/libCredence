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
//!  \file DwmCredenceServer.hh
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCESERVER_HH_
#define _DWMCREDENCESERVER_HH_

#include <boost/asio.hpp>

#include "DwmStreamIOCapable.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceXChaCha20Poly1305Istream.hh"
#include "DwmCredenceXChaCha20Poly1305Ostream.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    class Server
    {
    public:
      Server(const std::string & host, uint16_t port);
      bool Connect();
      bool Authenticate(const KeyStash & keyStash,
                        const KnownKeys & knownKeys);
      bool SendTo(const std::string & msg);
      bool SendTo(const StreamWritable & msg);
      bool ReceiveFrom(std::string & msg);
      bool ReceiveFrom(StreamReadable & msg);
      
    private:
      std::string                                  _host;
      uint16_t                                     _port;
      boost::asio::ip::tcp::iostream               _ios;
      std::string                                  _sharedKey;
      std::unique_ptr<XChaCha20Poly1305::Ostream>  _xos;
      std::unique_ptr<XChaCha20Poly1305::Istream>  _xis;
      
      bool ExchangeKeys();
      bool ExchangeIds(const KeyStash & keyStash, const KnownKeys & knownKeys,
                       Ed25519KeyPair & myKeys, std::string & serverPubKey);
      bool ExchangeChallenges(const std::string & mySecretKey,
                              const std::string & serverPubKey);
      
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCESERVER_HH_
