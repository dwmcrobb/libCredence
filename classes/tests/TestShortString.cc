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
//!  \file TestShortString.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::ShortString unit tests
//---------------------------------------------------------------------------

#include <sstream>
#include <stdexcept>

#include "DwmUnitAssert.hh"
#include "DwmCredenceShortString.hh"
#include "DwmCredenceUtils.hh"

using namespace std;
using namespace Dwm;

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestAssign()
{
  Credence::ShortString<5>  ss5;
  UnitAssert(decltype(ss5)::Size() == 5);
  ss5 = "Hello";
  UnitAssert(ss5.Value() == "Hello");

  bool gotLogicException = false;
  try {
    ss5 = "1234567890";
  }
  catch (std::logic_error & ex) {
    UnitAssert(ex.what() == std::string("Initializing string too long"));
    gotLogicException = true;
  }
  UnitAssert(gotLogicException);

  Credence::ShortString<5>  ss5_2 = ss5;
  UnitAssert(ss5_2.Value() == ss5.Value());

  Credence::ShortString<8>  ss8;
  UnitAssert(decltype(ss8)::Size() == 8);
  ss8.Assign(ss5);
  UnitAssert(ss8.Value() == ss5.Value());
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestIstreamOperator()
{
  std::stringstream  ss;
  const std::string  s30("123456789012345678901234567890");
  ss.write(s30.data(), s30.size());

  bool  gotException = false;
  Credence::ShortString<29>  ss29;
  UnitAssert(decltype(ss29)::Size() == 29);
  try {
    ss >> ss29;
  }
  catch (std::logic_error & ex) {
    UnitAssert(ex.what() == std::string("input too long"));
    gotException = true;
  }
  UnitAssert(true == gotException);
  gotException = false;
  ss.seekg(0);

  Credence::ShortString<30>  ss30;
  UnitAssert(decltype(ss30)::Size() == 30);
  try {
    ss >> ss30;
  }
  catch (std::logic_error & ex) {
    gotException = true;
  }
  UnitAssert(false == gotException);
  
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
static void TestStreamIO()
{
  Credence::ShortString<255> shortString =
    "0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=";
  UnitAssert(decltype(shortString)::Size() == 255);
  std::stringstream  ss;
  if (UnitAssert(shortString.Write(ss))) {
    Credence::ShortString<255>  shortString_2;
    if (UnitAssert(shortString_2.Read(ss))) {
      UnitAssert(shortString_2 == shortString);
    }
  }

  Credence::ShortString<65535>  shortString16 =
    "0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfV"
    "sOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ"
    "5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY"
    "93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPq"
    "edfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpR"
    "UVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUF"
    "qfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vs"
    "WGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8"
    "uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq2"
    "1UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhb"
    "d2vsWGPqedfVsOq21UUFqfSY93U=0YT8uJpRUVnJ5Rhbd2vsWGPqedfVsOq21UUFqfSY93U=";
  UnitAssert(decltype(shortString16)::Size() == 65535);
  ss.str("");
  if (UnitAssert(shortString16.Write(ss))) {
    Credence::ShortString<65535>  shortString16_2;
    if (UnitAssert(shortString16_2.Read(ss))) {
      UnitAssert(shortString16_2 == shortString16);
    }
  }

  ss.str("");
  if (UnitAssert(shortString.Write(ss))) {
    UnitAssert(! shortString16.Read(ss));
  }
  return;
}

//----------------------------------------------------------------------------
//!  
//----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  TestAssign();
  TestStreamIO();
  TestIstreamOperator();
  
  if (Assertions::Total().Failed()) {
    Assertions::Print(cerr, true);
    return 1;
  }
  else {
    cout << Assertions::Total() << " passed" << endl;
  }
  return 0;
}

