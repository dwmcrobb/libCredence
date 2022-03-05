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
//!  \file DwmCredenceXChaCha20Poly1305InBuffer.hh
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEXCHACHA20POLY1305INBUFFER_HH_
#define _DWMCREDENCEXCHACHA20POLY1305INBUFFER_HH_

#include <iostream>
#include <memory>
#include <string>

#include "DwmCredenceNonce.hh"

namespace Dwm {

  namespace Credence {
    
    namespace XChaCha20Poly1305 {

      //----------------------------------------------------------------------
      //!  This class is a helper for encrypted stream input.  It is used as
      //!  a streambuf for an istream.  It will buffer internally until a
      //!  a complete message is available, where a complete message is
      //!  comprised of nonce (initialization vector), length, data and MAC.
      //!
      //!  This class is typically not used directly, but is instantiated by
      //!  XChaCha20Poly1305::Istream.
      //----------------------------------------------------------------------
      class InBuffer
        : public std::streambuf
      {
      public:
        //--------------------------------------------------------------------
        //!  Construct from the given encrypted istream @c is and the
        //!  decryption key @c key.  @c key must be 32 bytes since we're
        //!  using XChaCha20.
        //--------------------------------------------------------------------
        InBuffer(std::istream & is, const std::string & key);

      protected:
        //--------------------------------------------------------------------
        //!  
        //--------------------------------------------------------------------
        int_type underflow() override;

      private:
        std::istream                  &_is;
        std::string                    _key;
        std::unique_ptr<char_type[]>   _buffer;
        
        //--------------------------------------------------------------------
        //!  Reads and decrypts the next message from the istream given in the
        //!  first argument of our constructor.  Places the decrypted data in
        //!  our internal buffer and returns the number of bytes in the
        //!  decrypted data.
        //--------------------------------------------------------------------
        int Reload();

        //--------------------------------------------------------------------
        //!  Just a helper to read the nonce and encrypted data from the
        //!  istream given in the first argument of our constructor, placing
        //!  the nonce in @c nonce and the encrypted data in @c cipherText.
        //--------------------------------------------------------------------
        bool LoadNonceAndCipherText(Nonce & nonce, std::string & cipherText);
      };

    }  // namespace XChaCha20Poly1305

  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEXCHACHA20POLY1305INBUFFER_HH_
