//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2024
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
//!  \file TestEd25519Key.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Ed25519Key unit tests
//---------------------------------------------------------------------------

#include <atomic>
#include <fstream>

#include "DwmUnitAssert.hh"
#include "DwmCredenceEd25519Key.hh"
#include "DwmCredenceUtils.hh"

using namespace std;
using namespace Dwm;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestAssign()
{
  Credence::Ed25519Key  key;
  UnitAssert(key.Id("test@mcplex.net") == "test@mcplex.net");
  UnitAssert(key.Id() == "test@mcplex.net");
  UnitAssert(key.KeyBase64("0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=")
             == "0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=");
  UnitAssert(key.KeyBase64()
             == "0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=");

  Credence::Ed25519Key
    key2("test@mcplex.net",
         Credence::Utils::Base642Bin("0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U="));
  UnitAssert(key2 == key);

  Credence::Ed25519Key  key3 = key;
  UnitAssert(key3 == key2);
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestIstream()
{
  {
    Credence::Ed25519Key  key;
    ifstream  is("inputs/id_ed25519.pub");
    if (UnitAssert(is)) {
      if (UnitAssert(is >> key)) {
        UnitAssert(key.Id() == "test@mcplex.net");
        string  s("0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=");
        UnitAssert(key.Key() == Credence::Utils::Base642Bin(s));
      }
      is.close();
    }
  }

  {
    Credence::Ed25519Key  key;
    ifstream  is("inputs/id_ed25519");
    if (UnitAssert(is)) {
      if (UnitAssert(is >> key)) {
        UnitAssert(key.Id() == "test@mcplex.net");
        string  s("7afut4mh7lBWdv6O6XBFR5UXky8kTRpmAtxtbDdfcXLRhPy4mlFRWcnl"
                  "GFt3a+xYY+p519Ww6rbVRQWp9Jj3dQ==");
        UnitAssert(key.Key() == Credence::Utils::Base642Bin(s));
      }
      is.close();
    }
  }
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestBadIstreams()
{
  {
    ifstream  is("inputs/bad_key_key_too_long");
    if (UnitAssert(is)) {
      Credence::Ed25519Key  key;
      UnitAssert(! (is >> key));
      UnitAssert(key.Id().empty());
      UnitAssert(key.Key().empty());
    }
  }

  {
    ifstream  is("inputs/bad_key_id_too_long");
    if (UnitAssert(is)) {
      Credence::Ed25519Key  key;
      UnitAssert(! (is >> key));
      UnitAssert(key.Id().empty());
      UnitAssert(key.Key().empty());
    }
  }

  {
    ifstream  is("/dev/null");
    if (UnitAssert(is)) {
      Credence::Ed25519Key  key;
      UnitAssert(! (is >> key));
      UnitAssert(key.Id().empty());
      UnitAssert(key.Key().empty());
      is.close();
    }
  }

  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestBadAssign()
{
  Credence::Ed25519Key  key;
  key.Id("test");
  string  s("123456789012345678901234567890123456789012345678901234567890"
            "123456789012345678901234567890123456789012345678901234567890"
            "123456789012345678901234567890123456789012345678901234567890"
            "123456789012345678901234567890123456789012345678901234567890"
            "1234567890123456");

  //  We should see an exception if we try to set the key content to
  //  a value that won't fit.
  bool  gotLogicError = false;
  try {
    key.Key(s);
  }
  catch (std::logic_error & ex) {
    gotLogicError = true;
  }
  UnitAssert(gotLogicError);

  //  We should see an exception if we try to set the id to a value
  //  that won't fit.
  gotLogicError = false;
  try {
    key.Id(s);
  }
  catch (std::logic_error & ex) {
    gotLogicError = true;
  }
  UnitAssert(gotLogicError);

  //  We should see an exception if we try to construct a key with
  //  an id that is too long.
  gotLogicError = false;
  try {
    Credence::Ed25519Key  badKey(s, s.substr(64));
  }
  catch (std::logic_error & ex) {
    gotLogicError = true;
  }
  UnitAssert(gotLogicError);

  //  We should see an exception if we try to construct a key with
  //  key content that is too long.
  gotLogicError = false;
  try {
    Credence::Ed25519Key  badKey(s.substr(64), s);
  }
  catch (std::logic_error & ex) {
    gotLogicError = true;
  }
  UnitAssert(gotLogicError);
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  TestAssign();
  TestIstream();
  TestBadAssign();
  TestBadIstreams();
  
  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
}

