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
//!  \file DwmCredenceXChaCha20Poly1305Istream.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::XChaCha20Poly1305::Istream class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEXCHACHA20POLY1305ISTREAM_HH_
#define _DWMCREDENCEXCHACHA20POLY1305ISTREAM_HH_

#include "DwmCredenceXChaCha20Poly1305InBuffer.hh"

namespace Dwm {

  namespace Credence {

    namespace XChaCha20Poly1305 {

      //----------------------------------------------------------------------
      //!  This class is essentially a filter for an istream.  It allows the
      //!  user of this class to read and decrypt an encrypted stream, hiding
      //!  all the details of decryption.  Think of it as a decrypting proxy
      //!  for any istream that sources encrypted data.
      //!
      //!  Since the C++ standard library does not include any socket
      //!  abstractions, the first argument to the constructor of this class
      //!  is usually an asio::ip::tcp::iostream (in the boost namespace if
      //!  you're using asio as bundled in Boost instead of standalone).  It
      //!  might also be an ifstream if we're reading encrypted data at rest.
      //!
      //!  Note how tiny this code is; all of the real extensibility is in the
      //!  std::streambuf, per the design of C++ iostreams.
      //----------------------------------------------------------------------
      class Istream
        : public std::istream
      {
      public:
        //--------------------------------------------------------------------
        //!  Construct with a reference to an existing encrypted istream @c is
        //!  and a 32-byte shared secret key which will be used to decrypt the
        //!  contents of @c is.
        //--------------------------------------------------------------------
        Istream(std::istream & is, const std::string & key)
            : std::istream(new InBuffer(is, key))
        {}
      
        //--------------------------------------------------------------------
        //!  Destructor.
        //--------------------------------------------------------------------
        virtual ~Istream()
        {
          delete rdbuf();
        }
      };
    
    }  // namespace XChaCha20Poly1305

  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEXCHACHA20POLY1305ISTREAM_HH_
