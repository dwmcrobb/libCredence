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
//!  \file DwmCredenceChallengeResponse.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::ChallengeResponse class implementation
//---------------------------------------------------------------------------

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceChallengeResponse.hh"
#include "DwmCredenceSigner.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool ChallengeResponse::Create(const Ed25519Key & signingKey,
                                   const Challenge & challenge)
    {
      bool  rc = false;
      if (! signingKey.Key().empty()) {
        if (! ((string)challenge).empty()) {
          rc = Signer::Sign(challenge, signingKey.Key(), _response);
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    istream & ChallengeResponse::Read(istream & is)
    {
      _response.clear();
      if (is) {
        StreamIO::Read(is, _response);
      }
      if (! is) {
        Syslog(LOG_ERR, "ChallengeResponse::Read() failed");
      }
      return is;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    ostream & ChallengeResponse::Write(ostream & os) const
    {
      if (os) {
        if (! StreamIO::Write(os, _response)) {
          Syslog(LOG_ERR, "ChallengeResponse::Write() failed");
        }
      }
      return os;
    }
    
    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool ChallengeResponse::Verify(const Ed25519Key & publicKey,
                                   const string & challengeString) const
    {
      bool    rc = false;
      string  signedContent;
      if (Signer::Open(_response, publicKey.Key(), signedContent)) {
        if (challengeString == signedContent) {
          rc = true;
        }
        else {
          FSyslog(LOG_ERR, "Challenge content mismatch: {} != {}",
                  Utils::Bin2Base64(challengeString),
                  Utils::Bin2Base64(signedContent));
        }
      }
      else {
        FSyslog(LOG_ERR, "ChallengeResponse::Verify({},{}) failed",
                Utils::Bin2Base64(publicKey.Key()),
                Utils::Bin2Base64(challengeString));
      }
      return rc;
    }
    
    
  }  // namespace Credence

}  // namespace Dwm
