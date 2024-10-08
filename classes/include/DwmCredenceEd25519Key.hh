//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2024
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
//!  \file DwmCredenceEd25519Key.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Ed25519Key class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEED25519PUBLICKEY_HH_
#define _DWMCREDENCEED25519PUBLICKEY_HH_

#include <iostream>
#include <string>

#include "DwmCredenceShortString.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulate an Ed25519 key: an identifier and the key content.  This
    //!  key is half of a key pair, and is used to represent a public key or
    //!  a private key.
    //------------------------------------------------------------------------
    class Ed25519Key
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor
      //----------------------------------------------------------------------
      Ed25519Key() = default;
      
      //----------------------------------------------------------------------
      //!  Copy constructor
      //----------------------------------------------------------------------
      Ed25519Key(const Ed25519Key &) = default;
      
      //----------------------------------------------------------------------
      //!  Move constructor
      //----------------------------------------------------------------------
      Ed25519Key(Ed25519Key &&) = default;
      
      //----------------------------------------------------------------------
      //!  Copy assignment
      //----------------------------------------------------------------------
      Ed25519Key & operator = (const Ed25519Key &) = default;
      
      //----------------------------------------------------------------------
      //!  Move assignment
      //----------------------------------------------------------------------
      Ed25519Key & operator = (Ed25519Key &&) = default;
      
      //----------------------------------------------------------------------
      //!  Construct from the given @c id and @c key.  Note that @c key
      //!  must be in the binary representation.
      //----------------------------------------------------------------------
      Ed25519Key(const std::string & id, const std::string & key);
      
      //----------------------------------------------------------------------
      //!  Returns the id.
      //----------------------------------------------------------------------
      const std::string & Id() const   { return _id.Value(); }

      //----------------------------------------------------------------------
      //!  Sets and returns the id.
      //----------------------------------------------------------------------
      const std::string & Id(const std::string & id)
      { _id = id;  return _id.Value(); }
      
      //----------------------------------------------------------------------
      //!  Returns the key content, in binary representation.
      //----------------------------------------------------------------------
      const std::string & Key() const  { return _key.Value(); }

      //----------------------------------------------------------------------
      //!  Sets and returns the key content, in binary representation.
      //!  @c key must be in the binary representation.
      //----------------------------------------------------------------------
      const std::string & Key(const std::string & key)
      { _key = key; return _key.Value(); }

      //----------------------------------------------------------------------
      //!  Returns the key content as a base64-encoded string.
      //----------------------------------------------------------------------
      std::string KeyBase64() const;

      //----------------------------------------------------------------------
      //!  Sets the key content from the base64-encoded string @c keyBase64.
      //!  Returns the key content as a base64-encoded string (which should
      //!  be the same as @c keyBase64).
      //----------------------------------------------------------------------
      std::string KeyBase64(const std::string & keyBase64);
      
      //----------------------------------------------------------------------
      //!  Reads the key from the given istream @c is.  Note that the key
      //!  content must be in binary representation.  Returns @c is.
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is);

      //----------------------------------------------------------------------
      //!  Writes the key to the given ostream @c os.  Note that the key
      //!  content is written in its binary representation.  Returns @c os.
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const;

      //----------------------------------------------------------------------
      //!  Clears the contents of the key (id and key content).
      //----------------------------------------------------------------------
      void Clear();
      
      //----------------------------------------------------------------------
      //!  Writes the key to the given ostream @c os, encoded in base64.
      //----------------------------------------------------------------------
      friend std::ostream &
      operator << (std::ostream & os, const Ed25519Key & pk);

      //----------------------------------------------------------------------
      //!  Reads the key from the given istream @c is, in human-readable form.
      //!  This is the form used when storing the key in a file, with the key
      //!  content represented in base64 encoding.
      //----------------------------------------------------------------------
      friend std::istream &
      operator >> (std::istream & is, Ed25519Key & pk);

      //----------------------------------------------------------------------
      //!  less-than operator
      //----------------------------------------------------------------------
      bool operator < (const Ed25519Key &) const;
      
      //----------------------------------------------------------------------
      //!  equality operator
      //----------------------------------------------------------------------
      bool operator == (const Ed25519Key &) const = default;
      
    private:
      ShortString<64>  _id;
      ShortString<64>  _key;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEED25519PUBLICKEY_HH_
