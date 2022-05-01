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
//!  \file credence.cc
//!  \author Daniel W. McRobb
//!  \brief credence key generator and checker (Ed25519 keys)
//---------------------------------------------------------------------------

#include "DwmArguments.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceVersion.hh"

using namespace std;

typedef   Dwm::Arguments<Dwm::Argument<'i',string>,
                         Dwm::Argument<'d',string>> KeyGenArgType;

typedef   Dwm::Arguments<Dwm::Argument<'d',string>> KeyCheckArgType;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void Usage(const char *argv0)
{
  cerr << "Usage: " << argv0 << " keygen [-i id] [-d directory]\n"
       << "       " << argv0 << " keycheck [-d directory]\n"
       << "       " << argv0 << " -v\n";
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void InitKeyGenArgs(KeyGenArgType & args)
{
  args.SetValueName<'i'>("identity");
  Dwm::Credence::Ed25519KeyPair  kp;
  args.SetHelp<'i'>("Use the given identity (defaults to " + kp.Id().Value() + ")");
  args.SetValueName<'d'>("directory");
  args.SetHelp<'d'>("directory in which to store keys (defaults to ~/.credence)");
  args.Set<'d'>("~/.credence");
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void InitKeyCheckArgs(KeyCheckArgType & args)
{
  args.SetValueName<'d'>("directory");
  args.SetHelp<'d'>("key directory (defaults to ~/.credence)");
  args.Set<'d'>("~/.credence");
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static bool CheckKeyStash(const string & keyDir)
{
  Dwm::Credence::KeyStash  keyStash(keyDir);
  return keyStash.IsValid();
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  KeyCheckArgType  keycheckArgs;
  KeyGenArgType    keygenArgs;
  InitKeyCheckArgs(keycheckArgs);
  InitKeyGenArgs(keygenArgs);

  if (argc < 2) {
    Usage(argv[0]);
    return 1;
  }
  else {
    if (string(argv[1]) == "keygen") {
      int  argind = keygenArgs.Parse(argc-1, &argv[1]);
      if (argind < 0) {
        cerr << keygenArgs.Usage(string(argv[0]) + ' ' + argv[1], "");
        return 1;
      }
      Dwm::Credence::Ed25519KeyPair  keys(keygenArgs.Get<'i'>());
      Dwm::Credence::KeyStash        keyStash(keygenArgs.Get<'d'>());
      if (keyStash.Save(keys)) {
        return 0;
      }
    }
    else if (string(argv[1]) == "keycheck") {
      int  argind = keycheckArgs.Parse(argc-1, &argv[1]);
      if (argind < 0) {
        cerr << keycheckArgs.Usage(string(argv[0]) + ' ' + argv[1], "");
        return 1;
      }
      if (CheckKeyStash(keycheckArgs.Get<'d'>())) {
        cout << "Valid key stash '" << keycheckArgs.Get<'d'>() << "'\n";
        return 0;
      }
      else {
        cerr << "Invalid key stash '" << keycheckArgs.Get<'d'>() << "'\n";
        return 1;
      }
    }
    else if (string(argv[1]) == "-v") {
      cout << Dwm::Credence::Version.Version() << '\n';
      return 0;
    }
    else {
      Usage(argv[0]);
      return 1;
    }
  }
  
  return 1;
}
