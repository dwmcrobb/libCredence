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
//!  \file DwmCredenceSigner.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Signer class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCESIGNER_HH_
#define _DWMCREDENCESIGNER_HH_

#include <string>

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates message signing and opening of signed messages.
    //------------------------------------------------------------------------
    class Signer
    {
    public:
      //----------------------------------------------------------------------
      //!  Signs the given @c message with the given @c signingKey, storing
      //!  the signed message in @c signedMessage.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      static bool Sign(const std::string & message,
                       const std::string & signingKey,
                       std::string & signedMessage);
      
      //----------------------------------------------------------------------
      //!  Opens the given @c signedMessage that must have been signed by
      //!  the owner of the given @c publicKey, storing the contents of the
      //!  signed message in @c message.  Returns true on success, false on
      //!  failure.
      //----------------------------------------------------------------------
      static bool Open(const std::string & signedMessage,
                       const std::string & publicKey,
                       std::string & message);
    };

  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCESIGNER_HH_
