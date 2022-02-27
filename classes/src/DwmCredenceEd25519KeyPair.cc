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
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    Ed25519KeyPair::Ed25519KeyPair(const string & id)
        : _id(id)
    {
      if (_id.empty()) {
        _id = Utils::UserName() + '@' + Utils::HostName();
      }
      
      unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
      unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
      
      crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);
      _publicKey.assign((const char *)ed25519_pk,
                        crypto_sign_ed25519_PUBLICKEYBYTES);
      _secretKey.assign((const char *)ed25519_skpk,
                        crypto_sign_ed25519_SECRETKEYBYTES);
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
    const string & Ed25519KeyPair::Id() const
    {
      return _id;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    const string & Ed25519KeyPair::Id(const string & id)
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
    void Ed25519KeyPair::Clear()
    {
      _id.assign(_id.size(), '\0');
      _id.clear();
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
      return ((_id == keyPair._id)
              && (_publicKey == keyPair._publicKey)
              && (_secretKey == keyPair._secretKey));
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
