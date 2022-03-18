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
//!  \file DwmCredencePeer.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Peer class implementation
//---------------------------------------------------------------------------

#include "DwmCredenceAuthenticator.hh"
#include "DwmCredencePeer.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Peer::Peer(boost::asio::ip::tcp::socket && s)
        : _ios(std::move(s)), _theirId(), _xis(nullptr), _xos(nullptr)
    {}
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Peer::Authenticate(const KeyStash & keyStash,
                            const KnownKeys & knownKeys)
    {
      bool  rc = false;
      _theirId.clear();
      Authenticator  authenticator(keyStash, knownKeys);
      string  agreedKey;
      if (authenticator.Authenticate(_ios, _theirId, agreedKey)) {
        _xis = make_unique<XChaCha20Poly1305::Istream>(_ios, agreedKey);
        _xos = make_unique<XChaCha20Poly1305::Ostream>(_ios, agreedKey);
        rc = true;
      }
      return rc;
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
