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
//!  \file credence-keygen.cc
//!  \author Daniel W. McRobb
//!  \brief credence key generator (Ed25519 keys)
//---------------------------------------------------------------------------

#include "DwmArguments.hh"
#include "DwmCredenceKeyStash.hh"

using namespace std;

typedef   Dwm::Arguments<Dwm::Argument<'i',string>,
                         Dwm::Argument<'d',string>> MyArgType;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void InitArgs(MyArgType & args)
{
  args.SetValueName<'i'>("identity");
  args.SetHelp<'i'>("Use the given identity");
  args.SetValueName<'d'>("directory");
  args.SetHelp<'d'>("directory in which to store keys");
  args.Set<'d'>("~/.credence");
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  MyArgType  args;
  InitArgs(args);

  int  argind = args.Parse(argc, argv);
  if (argind < 0) {
    cerr << args.Usage(argv[0],"");
    return 1;
  }

  Dwm::Credence::Ed25519KeyPair  keys(args.Get<'i'>());
  Dwm::Credence::KeyStash        keyStash(args.Get<'d'>());
  if (keyStash.Save(keys)) {
    return 0;
  }
  return 1;
}
