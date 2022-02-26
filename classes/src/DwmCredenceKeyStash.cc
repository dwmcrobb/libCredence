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
//!  \file DwmCredenceKeyStash.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KeyStash class implementation
//---------------------------------------------------------------------------

extern "C" {
  #include <sodium.h>
}

#include <fstream>

#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    KeyStash::KeyStash(const string & dirName)
        : _dirName(dirName)
    {}
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyStash::Save(const Ed25519KeyPair & edkp)
    {
      bool  rc = false;
      if (SavePublicKey(edkp)) {
        rc = SaveSecretKey(edkp);
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyStash::Get(Ed25519KeyPair & edkp)
    {
      bool  rc = false;
      edkp.Clear();
      if (GetPublicKey(edkp)) {
        rc = GetSecretKey(edkp);
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyStash::SavePublicKey(const Ed25519KeyPair & edkp) const
    {
      bool      rc = false;
      string    savePath = _dirName + "/id_ed25519.pub";
      ofstream  os(savePath);
      if (os) {
        os << edkp.Id() << " ed25519 " << Utils::Bin2Base64(edkp.PublicKey());
        rc = true;
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyStash::SaveSecretKey(const Ed25519KeyPair & edkp) const
    {
      bool      rc = false;
      string    savePath = _dirName + "/id_ed25519";
      ofstream  os(savePath);
      if (os) {
        os << edkp.Id() << " ed25519 " << Utils::Bin2Base64(edkp.SecretKey());
        rc = true;
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyStash::GetPublicKey(Ed25519KeyPair & edkp) const
    {
      bool      rc = false;
      ifstream  is(_dirName + "/id_ed25519.pub");
      if (is) {
        string  id, keyType, encodedKey;
        is >> id >> keyType >> encodedKey;
        if ((! id.empty())
            && (! encodedKey.empty())
            && (keyType == "ed25519")) {
          unsigned char  binaryKey[crypto_sign_ed25519_PUBLICKEYBYTES];
          if (sodium_base642bin(binaryKey, crypto_sign_ed25519_PUBLICKEYBYTES,
                                encodedKey.data(), encodedKey.size(),
                                nullptr, 0, nullptr,
                                sodium_base64_VARIANT_ORIGINAL) == 0) {
            edkp.Id(id);
            string  keyString((const char *)binaryKey,
                              crypto_sign_ed25519_PUBLICKEYBYTES);
            edkp.PublicKey(keyString);
            rc = true;
          }
        }
      }
      return rc;
    }
      
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool KeyStash::GetSecretKey(Ed25519KeyPair & edkp) const
    {
      bool  rc = false;
      ifstream  is(_dirName + "/id_ed25519");
      if (is) {
        string  id, keyType, encodedKey;
        is >> id >> keyType >> encodedKey;
        if ((id == edkp.Id())
            && (keyType == "ed25519")
            && (! encodedKey.empty())) {
          unsigned char  binaryKey[crypto_sign_ed25519_SECRETKEYBYTES];
          if (sodium_base642bin(binaryKey, crypto_sign_ed25519_SECRETKEYBYTES,
                                encodedKey.data(), encodedKey.size(),
                                nullptr, 0, nullptr,
                                sodium_base64_VARIANT_ORIGINAL) == 0) {
            string  keyString((const char *)binaryKey,
                              crypto_sign_ed25519_SECRETKEYBYTES);
            edkp.SecretKey(keyString);
            rc = true;
          }
        }
      }
      return rc;
    }
    

  }  // namespace Credence

}  // namespace Dwm
