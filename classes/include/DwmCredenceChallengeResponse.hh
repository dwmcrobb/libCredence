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
//!  \file DwmCredenceChallengeResponse.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::ChallengeResponse class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCECHALLENGERESPONSE_HH_
#define _DWMCREDENCECHALLENGERESPONSE_HH_

#include <string>

#include "DwmCredenceChallenge.hh"
#include "DwmCredenceEd25519PublicKey.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulates a challenge response.  This is used when responding
    //!  to a Challenge during authentication to a client or server.
    //------------------------------------------------------------------------
    class ChallengeResponse
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor.
      //----------------------------------------------------------------------
      ChallengeResponse() = default;
      
      //----------------------------------------------------------------------
      //!  Default copy constructor.
      //----------------------------------------------------------------------
      ChallengeResponse(const ChallengeResponse &) = default;
      
      //----------------------------------------------------------------------
      //!  Given a @c challenge, creates the response using the given
      //!  @c signingKey.  Returns true on success, false on failure.
      //----------------------------------------------------------------------
      bool Create(const std::string & signingKey,
                  const Challenge & challenge);
      
      //----------------------------------------------------------------------
      //!  Reads the challenge response from the given istream @c is.
      //!  Returns @c is.  @c is is normally a reference to an
      //!  XChaCha20Poly1305::Istream (an encrypted stream).
      //----------------------------------------------------------------------
      std::istream & Read(std::istream & is);
      
      //----------------------------------------------------------------------
      //!  Writes the challenge response to the given ostream @c os.
      //!  Returns @c os.  @c os is normally a reference to an
      //!  XChaCha20Poly1305::Ostream (an encrypted stream).
      //----------------------------------------------------------------------
      std::ostream & Write(std::ostream & os) const;
      
      //----------------------------------------------------------------------
      //!  Using the given @c publicKey of the source of the response,
      //!  verifies that the response was signed by the source and that the
      //!  response contents matches the given @c challengeString.  Returns
      //!  true if the response is correct, else returns false.
      //----------------------------------------------------------------------
      bool Verify(const Ed25519PublicKey & publicKey,
                  const std::string & challengeString) const;
      
    private:
      std::string  _response;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCECHALLENGERESPONSE_HH_
