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
//!  \file TestKnownKeys.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::KnownKeys unit tests
//---------------------------------------------------------------------------

#include <filesystem>
#include <sstream>

#include "DwmUnitAssert.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceUtils.hh"

using namespace std;
using namespace Dwm;

static string  g_myDir;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void SetMyDir(const char *argv0)
{
  namespace  fs = std::filesystem;
  
  g_myDir = fs::path(argv0).parent_path();
  if (fs::path(g_myDir).filename() == ".libs") {
    g_myDir = fs::path(g_myDir).parent_path();
  }
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestAdminKeys()
{
  Credence::KnownKeys  knownKeys(g_myDir + "/inputs", "admin_keys");
  UnitAssert(knownKeys.Keys().size() == 2);
  string   key = knownKeys.Find("test@mcplex.net");
  UnitAssert(! key.empty());
  key = knownKeys.Find("foo@somedomain.com");
  UnitAssert(! key.empty());
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestBadKeys()
{
  Credence::KnownKeys  knownKeys(g_myDir + "/inputs", "bad_keys");
  UnitAssert(knownKeys.Keys().size() == 2);
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static bool KnownKeysOK(const Credence::KnownKeys & knownKeys)
{
  bool  rc = true;
  rc &= UnitAssert(knownKeys.Keys().size() == 3);
  string   key = knownKeys.Find("test@mcplex.net");
  rc &= UnitAssert(! key.empty());
  key = knownKeys.Find("foo@somedomain.com");
  rc &= UnitAssert(! key.empty());
  key = knownKeys.Find("bar@anotherdomain.com");
  rc &= UnitAssert(! key.empty());

  return rc;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void WriteReadKeys(Credence::KnownKeys & knownKeys)
{
  std::stringstream  ss;
  if (UnitAssert(knownKeys.Write(ss))) {
    knownKeys.ClearKeys();
    UnitAssert(knownKeys.Keys().empty());
    UnitAssert(knownKeys.Read(ss));
  }
  return;
}
  
//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  SetMyDir(argv[0]);
  
  TestAdminKeys();

  Credence::KnownKeys  knownKeys(g_myDir + "/inputs");
  UnitAssert(KnownKeysOK(knownKeys));

  knownKeys.Reload();
  UnitAssert(KnownKeysOK(knownKeys));

  WriteReadKeys(knownKeys);
  UnitAssert(KnownKeysOK(knownKeys));

  TestBadKeys();
  
  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
}

