//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2024
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
//!  \file DwmCredenceEd25519KeyPair.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Ed25519KeyPair class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEED25519KEYPAIR_HH_
#define _DWMCREDENCEED25519KEYPAIR_HH_

#include "DwmCredenceEd25519Key.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates an Ed25519 key pair.  The contained secret key is used
    //!  to sign challenge responses during authentication.  The contained
    //!  public key is used to validate signatures in challenge responses
    //!  during authentication.
    //------------------------------------------------------------------------
    class Ed25519KeyPair
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor.  Creates the contained public and secret keys
      //!  using random data.  If @c id is empty, an ID consisting of the
      //!  local user name and hostname will be used (e.g. 'dwm@host.org').
      //----------------------------------------------------------------------
      Ed25519KeyPair(const std::string & id = "");
      
      //----------------------------------------------------------------------
      //!  Copy constructor.
      //----------------------------------------------------------------------
      Ed25519KeyPair(const Ed25519KeyPair &) = default;

      //----------------------------------------------------------------------
      //!  Destructor.  Clears the contents of the keys before deallocation.
      //----------------------------------------------------------------------
      ~Ed25519KeyPair();

      //----------------------------------------------------------------------
      //!  Returns the public key.  This is used to verify signatures in
      //!  challenge responses during authentication.
      //----------------------------------------------------------------------
      const Ed25519Key & PublicKey() const;
      
      //----------------------------------------------------------------------
      //!  Sets and returns the public key.
      //----------------------------------------------------------------------
      const Ed25519Key & PublicKey(const Ed25519Key & publicKey);
      
      //----------------------------------------------------------------------
      //!  Returns the secret key.  This is used to sign challenge responses
      //!  during authentication.
      //----------------------------------------------------------------------
      const Ed25519Key & SecretKey() const;
      
      //----------------------------------------------------------------------
      //!  Sets and returns the secret key.
      //----------------------------------------------------------------------
      const Ed25519Key & SecretKey(const Ed25519Key & secretKey);

      //----------------------------------------------------------------------
      //!  Returns true if they keypair is valid (i.e. can be used to sign
      //!  messages).
      //----------------------------------------------------------------------
      bool IsValid() const;
      
      //----------------------------------------------------------------------
      //!  Clears the contents of the key pair.
      //----------------------------------------------------------------------
      void Clear();
      
      //----------------------------------------------------------------------
      //!  operator ==
      //----------------------------------------------------------------------
      bool operator == (const Ed25519KeyPair & keyPair) const;
      
    private:
      Ed25519Key  _publicKey;
      Ed25519Key  _secretKey;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEED25519KEYPAIR_HH_
