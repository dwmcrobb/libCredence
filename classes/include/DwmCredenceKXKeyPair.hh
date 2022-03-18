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
//!  \file DwmCredenceKXKeyPair.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KXKeyPair class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEKXKEYPAIR_HH_
#define _DWMCREDENCEKXKEYPAIR_HH_

#include <string>

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates a key exchange key pair.
    //------------------------------------------------------------------------
    class KXKeyPair
    {
    public:
      //----------------------------------------------------------------------
      //!  Creates a key exchange key pair with random content.
      //----------------------------------------------------------------------
      KXKeyPair();
      
      //----------------------------------------------------------------------
      //!  Clears the keys before destroying them.
      //----------------------------------------------------------------------
      ~KXKeyPair();
      
      //----------------------------------------------------------------------
      //!  Returns a const reference to the public key.
      //----------------------------------------------------------------------
      const std::string & PublicKey() const;
      
      //----------------------------------------------------------------------
      //!  Returns a const reference to the secret key.
      //----------------------------------------------------------------------
      const std::string & SecretKey() const;
      
      //----------------------------------------------------------------------
      //!  Given a client's public key, returns a shared key that will
      //!  match the shared key created on the client side with
      //!  ClientSharedKey().
      //----------------------------------------------------------------------
      std::string ServerSharedKey(const std::string & clientPublicKey) const;
      
      //----------------------------------------------------------------------
      //!  Given a server's public key, returns a shared key that will
      //!  match the shared key created on the server side with
      //!  ServerSharedKey().
      //----------------------------------------------------------------------
      std::string ClientSharedKey(const std::string & serverPublicKey) const;

      std::string SharedKey(const std::string & theirPublicKey) const;

    private:
      std::string  _publicKey;
      std::string  _secretKey;

    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEKXKEYPAIR_HH_
