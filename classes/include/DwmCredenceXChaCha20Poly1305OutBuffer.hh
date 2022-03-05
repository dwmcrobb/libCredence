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
//!  \file DwmCredenceXChaCha20Poly1305OutBuffer.hh
//!  \author Daniel W. McRobb
//!  \brief NOT YET DOCUMENTED
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEXCHACHA20POLY1305OUTBUFFER_HH_
#define _DWMCREDENCEXCHACHA20POLY1305OUTBUFFER_HH_

#include <iostream>
#include <string>

namespace Dwm {

  namespace Credence {

    namespace XChaCha20Poly1305 {

      //----------------------------------------------------------------------
      //!  This class is a helper for encrypted stream output.  It is used as
      //!  a streambuf for an ostream.  It will buffer internally until
      //!  flush() is called on the ostream that owns the buffer (which will
      //!  end up calling our sync() member).  When our sync() member is
      //!  called, we will write a random nonce (initialization vector), the
      //!  encrypted data and the MAC to the associated ostream that was
      //!  passed as the first argument of the constructor.  In other words,
      //!  message packaging and transmission occurs whenever our sync()
      //!  member is called.
      //!
      //!  This class is typically not used directly, but is instead
      //!  instantiated by Dwm::Credence::XChaCha20Poly1305::Ostream.
      //----------------------------------------------------------------------
      class OutBuffer
        : public std::streambuf
      {
      public:
        //--------------------------------------------------------------------
        //!  Construct with the given ostream @c os and encryption key @c key.
        //--------------------------------------------------------------------
        OutBuffer(std::ostream & os, const std::string & key);
        
      protected:
        int_type overflow(int_type c) override;
        int sync() override;
        std::streamsize xsputn(const char *p, std::streamsize n) override;

      private:
        std::ostream    & _os;
        std::string       _key;
        std::string       _plainbuf;
      };
      

    }  // namespace XChaCha20Poly1305

  }  // namespace Credence

}  // namespace Dwm
      
#endif  // _DWMCREDENCEXCHACHA20POLY1305OUTBUFFER_HH_
