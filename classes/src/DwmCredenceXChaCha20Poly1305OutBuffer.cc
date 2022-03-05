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
//!  \file DwmCredenceXChaCha20Poly1305OutBuffer.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::XChaCha20Poly1305::OutBuffer class implementation
//---------------------------------------------------------------------------

#include "DwmCredenceXChaCha20Poly1305.hh"
#include "DwmCredenceXChaCha20Poly1305OutBuffer.hh"

namespace Dwm {

  namespace Credence {

    namespace XChaCha20Poly1305 {

      using namespace std;
      
      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      OutBuffer::OutBuffer(std::ostream & os, const std::string & key)
          : _os(os)
      {
        if (crypto_generichash_BYTES <= key.size()) {
          _key = key;
        }
        else {
          throw std::logic_error("key not long enough!");
        }
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      OutBuffer::int_type OutBuffer::overflow(int_type c)
      {
        if (! traits_type::eq_int_type(c, traits_type::eof())) {
          _plainbuf += traits_type::to_char_type(c);
          return c;
        }
        return traits_type::eof();
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      std::streamsize OutBuffer::xsputn(const char *p, std::streamsize n)
      {
        _plainbuf.append(p, n);
        return n;
      }

      //----------------------------------------------------------------------
      //!  
      //----------------------------------------------------------------------
      int OutBuffer::sync()
      {
        int  rc = -1;
        Nonce  nonce;
        if (nonce.Write(_os)) {
          string  cipherText;
          if (Encrypt(cipherText, _plainbuf, nonce, _key)) {
            if (_os.write(cipherText.c_str(), cipherText.size())) {
              if (_os.flush()) {
                rc = 0;
              }
            }
          }
        }
        _plainbuf.clear();
        return rc;
      }
      
    }  // namespace XChaCha20Poly1305

  }  // namespace Credence

}  // namespace Dwm
