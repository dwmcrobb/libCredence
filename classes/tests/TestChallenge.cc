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
//!  \file TestChallenge.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Challenge unit tests
//---------------------------------------------------------------------------

#include <sstream>

#include "DwmSysLogger.hh"
#include "DwmUnitAssert.hh"
#include "DwmCredenceChallengeResponse.hh"
#include "DwmCredenceEd25519KeyPair.hh"
#include "DwmCredenceSigner.hh"
#include "DwmCredenceUtils.hh"

using namespace std;
using namespace Dwm;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestIO()
{
  Credence::Ed25519KeyPair  keyPair("dwm");
  Credence::Challenge       challenge(true);
  Credence::ChallengeResponse  response;
  UnitAssert(response.Create(keyPair.SecretKey(), challenge));

  stringstream  ss;
  UnitAssert(response.Write(ss));
  Credence::ChallengeResponse  response2;
  UnitAssert(response2.Read(ss));
  UnitAssert(response2.Verify(keyPair.PublicKey(), challenge));
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  Dwm::SysLogger::Open("TestChallenge", LOG_PID|LOG_PERROR, LOG_USER);
  
  Credence::Ed25519KeyPair  keyPair("dwm");
  Credence::Challenge       challenge(true);
  string                    signedMessage;
  
  if (UnitAssert(Credence::Signer::Sign(challenge,
                                        keyPair.SecretKey(), signedMessage))) {
    Credence::ChallengeResponse  response;
    UnitAssert(response.Create(keyPair.SecretKey(), challenge));
    UnitAssert(response.Verify(keyPair.PublicKey(), challenge));
    
    // UnitAssert(challenge.Verify(signedMessage));
  }

  TestIO();
  
  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
}

