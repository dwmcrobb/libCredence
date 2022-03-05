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
//!  \file DwmCredenceXChaCha20Poly1305Ostream.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::XChaCha20Poly1305::Ostream class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEXCHACHA20POLY1305OSTREAM_HH_
#define _DWMCREDENCEXCHACHA20POLY1305OSTREAM_HH_

#include "DwmCredenceXChaCha20Poly1305OutBuffer.hh"

namespace Dwm {

  namespace Credence {

    namespace XChaCha20Poly1305 {

      //----------------------------------------------------------------------
      //!  This class is essentially a filter for an existing ostream,
      //!  allowing the user to encrypt data to that ostream using any
      //!  of the usual ostream interface.  This hides all of the
      //!  encryption details under the hood, except for the fact that
      //!  the user will need to call flush() whenever they want data to
      //!  be sent to the destination ostream.  This is a consequence of
      //!  needing an authenticated encryption scheme, and hence a need
      //!  to encapsulate an initialization vector, encrypted data and a
      //!  message authentication code.  An instance of this class will
      //!  buffer encrypted data internally until the flush() member is
      //!  called.  When flush() is called (which in the end will
      //!  trigger the associated streambuf's sync()), we package up the
      //!  initialization vector, a message length field, the encrypted
      //!  data and the message authentication code and write it all to
      //!  the destination ostream.  Note that there is a 48 byte
      //!  overhead each time we do this; a 24-byte initialization
      //!  vector, an 8-byte length field and a 16-byte message
      //!  authentication code.  So instead of choosing a message
      //!  demarcation under the hood, we leave it to the user of this
      //!  class to decide when they'd like to flush the internal
      //!  buffer.  Note the implicit memory versus bandwidth tradeoff:
      //!  flushing more frequently will reduce buffer memory
      //!  consumption but cause an increase in on-the-wire overhead.
      //!
      //!  Since the C++ standard library does not include any socket
      //!  abstractions, the first argument to the constructor of this
      //!  class is often an asio::ip::tcp::iostream (in the boost
      //!  namespace if you're using asio as bundled in Boost instead of
      //!  standalone).  It might also be an ofstream if we're writing
      //!  encrypted data at rest.  It could of course also be an
      //!  ostringstream.
      //!  
      //!  Note how tiny this code is; all of the real extensibility is
      //!  in the std::streambuf, per the design of C++ iostreams.
      //----------------------------------------------------------------------
      class Ostream
        : public std::ostream
      {
      public:
        //--------------------------------------------------------------------
        //!  Construct with a reference to the destination ostream @c os and
        //!  the 32-byte encryption key.  Notice that all this does is call
        //!  the base constructor with a new instance of an OutBuffer.
        //--------------------------------------------------------------------
        Ostream(std::ostream & os, const std::string & key)
            : std::ostream(new OutBuffer(os, key))
        {}
      
        //--------------------------------------------------------------------
        //!  Destructor.
        //--------------------------------------------------------------------
        virtual ~Ostream()
        {
          delete rdbuf();
        }
      };
      
    }  // namespace XChaCha20Poly1305

  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEXCHACHA20POLY1305OSTREAM_HH_
