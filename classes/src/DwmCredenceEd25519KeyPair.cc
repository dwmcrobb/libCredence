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
//!  \file DwmCredenceEd25519KeyPair.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Ed25519KeyPair class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include "DwmCredenceEd25519KeyPair.hh"
#include "DwmCredenceSigner.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Ed25519KeyPair::Ed25519KeyPair(const string & id)
        : _id(id), _publicKey(crypto_sign_ed25519_PUBLICKEYBYTES, '\0'),
          _secretKey(crypto_sign_ed25519_SECRETKEYBYTES, '\0')
    {
      if (_id.Value().empty()) {
        _id = Utils::UserName() + '@' + Utils::HostName();
      }
      crypto_sign_ed25519_keypair((uint8_t *)_publicKey.data(),
                                  (uint8_t *)_secretKey.data());
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Ed25519KeyPair::~Ed25519KeyPair()
    {
      Clear();
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const ShortString<255> & Ed25519KeyPair::Id() const
    {
      return _id;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const ShortString<255> & Ed25519KeyPair::Id(const ShortString<255> & id)
    {
      _id = id;
      return _id;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & Ed25519KeyPair::PublicKey() const
    {
      return _publicKey;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & Ed25519KeyPair::PublicKey(const string & publicKey)
    {
      _publicKey = publicKey;
      return _publicKey;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & Ed25519KeyPair::SecretKey() const
    {
      return _secretKey;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & Ed25519KeyPair::SecretKey(const string & secretKey)
    {
      _secretKey = secretKey;
      return _secretKey;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Ed25519KeyPair::IsValid() const
    {
      bool  rc = false;
      if ((! _publicKey.empty()) && (! _secretKey.empty())) {
        string  origMessage(32, '\0');
        randombytes_buf((void *)origMessage.data(), 32);
        string  signedMessage;
        if (Signer::Sign(origMessage, _secretKey, signedMessage)) {
          string  openedMessage;
          if (Signer::Open(signedMessage, _publicKey, openedMessage)) {
            rc = (openedMessage == origMessage);
          }
        }
      }
      return rc;
    }
      
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    void Ed25519KeyPair::Clear()
    {
      // _id.assign(_id.size(), '\0');
      // _id.clear();
      _publicKey.assign(_publicKey.size(), '\0');
      _publicKey.clear();
      _secretKey.assign(_secretKey.size(), '\0');
      _secretKey.clear();
      return;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Ed25519KeyPair::operator == (const Ed25519KeyPair & keyPair) const
    {
      return ((_id.Value() == keyPair._id.Value())
              && (_publicKey == keyPair._publicKey)
              && (_secretKey == keyPair._secretKey));
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
