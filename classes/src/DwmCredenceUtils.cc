//===========================================================================
// @(#) $DwmPath$
//===========================================================================
//  Copyright (c) Daniel W. McRobb 2022, 2023, 2024
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
//!  \file DwmCredenceUtils.cc
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Utils class implementation
//---------------------------------------------------------------------------

extern "C" {
#if (defined(__unix__) || defined(unix) || defined(__unix)) || defined(__APPLE__)
  #include <sys/types.h>
  #include <sys/select.h>
  #include <unistd.h>
  #include <pwd.h>
  #if defined(__APPLE__)
    #include <uuid/uuid.h>
  #endif
#elif defined(_WIN32)
  #include <winsock.h>
#endif
  #include <sodium.h>
}

#include <cstdlib>
#include <thread>

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceUtils.hh"

namespace Dwm {

  namespace Credence {

    using namespace std;

    //------------------------------------------------------------------------
    template <typename SocketT>
    ssize_t ASIO_BytesReady(SocketT & sck)
    {
      ssize_t  rc = -1;
      try {
        size_t  bytesReady = sck.available();
        rc = bytesReady;
      }
      catch (...) {
      }
      return rc;
    }
    
    //------------------------------------------------------------------------
    ssize_t Utils::BytesReady(BoostTcpSocket & sck)
    { return ASIO_BytesReady(sck); }

    //------------------------------------------------------------------------
    ssize_t Utils::BytesReady(BoostUnixSocket & sck)
    { return ASIO_BytesReady(sck); }

    //------------------------------------------------------------------------
    template <typename SocketT>
    bool ASIO_WaitUntilBytesReady(SocketT & sck,
                                  uint32_t numBytes, Utils::TimePoint endTime)
    {
      bool  rc = false;
      if (sck.is_open()) {
        ssize_t  bytesReady = 0;
        while ((bytesReady = Utils::BytesReady(sck)) < numBytes) {
          if (Utils::Clock::now() > endTime) {
            FSyslog(LOG_DEBUG, "Gave up waiting for {} bytes",
                    numBytes - bytesReady);
            break;
          }
          else if (bytesReady < 0) {
            Syslog(LOG_DEBUG, "Error on socket");
            break;
          }
          else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        }
        rc = (bytesReady >= numBytes);
      }
      return rc;
    }
      
    //------------------------------------------------------------------------
    bool Utils::WaitUntilBytesReady(BoostTcpSocket & sck, uint32_t numBytes,
                                    TimePoint endTime)
    { return ASIO_WaitUntilBytesReady(sck, numBytes, endTime); }

    //------------------------------------------------------------------------
    bool Utils::WaitUntilBytesReady(BoostUnixSocket & sck, uint32_t numBytes,
                                    TimePoint endTime)
    { return ASIO_WaitUntilBytesReady(sck, numBytes, endTime); }
    
    //------------------------------------------------------------------------
    bool Utils::WaitForBytesReady(BoostTcpSocket & sck,
                                  uint32_t numBytes,
                                  std::chrono::milliseconds timeout)
    { return WaitUntilBytesReady(sck, numBytes, Clock::now() + timeout); }

    //------------------------------------------------------------------------
    bool Utils::WaitForBytesReady(BoostUnixSocket & sck, uint32_t numBytes,
                                  std::chrono::milliseconds timeout)
    { return WaitUntilBytesReady(sck, numBytes, Clock::now() + timeout); }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string Utils::Bin2Base64(const string & s)
    {
      static const int  variant = sodium_base64_VARIANT_ORIGINAL;
      
      string  rc;
      if (! s.empty()) {
        size_t  outlen =
          sodium_base64_encoded_len(s.size(), variant);
        char    *tmp = (char *)calloc(1, outlen);
        if (tmp) {
          sodium_bin2base64(tmp, outlen,
                            (const unsigned char *)s.data(), s.size(),
                            variant);
          rc = tmp;
          free(tmp);
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string Utils::Base642Bin(const string & s)
    {
      static const int  variant = sodium_base64_VARIANT_ORIGINAL;
      string  rc;
      if (! s.empty()) {
        size_t   buflen = (s.size() * 3) / 4;
        try {
          rc.resize(buflen);
          size_t   binlen;
          if (sodium_base642bin((uint8_t *)rc.data(), buflen, s.data(),
                                s.size(), nullptr, &binlen, nullptr,
                                sodium_base64_VARIANT_ORIGINAL) == 0) {
            rc.resize(binlen);
          }
          else {
            Syslog(LOG_ERR, "sodium_base642bin() failed!");
            rc.clear();
          }
        }
        catch (...) {
          FSyslog(LOG_ERR, "rc.resize({}) failed!", buflen);
        }
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string Utils::UserHomeDirectory()
    {
      string  rc;
#if (defined(__unix__) || defined(unix) || defined(__unix)) || defined(__APPLE__)
      int    buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
      if (buflen > 0) {
        //  Use password entry for user ID
        char  *buf = (char *)malloc(buflen);
        if (buf) {
          struct passwd  pwd, *result = nullptr;
          if (getpwuid_r(getuid(), &pwd, buf, buflen, &result) == 0) {
            rc = pwd.pw_dir;
          }
          free(buf);
        }
      }
      else {
        //  Use environment
        char  *home = getenv("HOME");
        if (home) {
          rc = home;
        }
      }
#elif defined(_WIN32)
      //  Use environment
      char  *home = getenv("USERPROFILE");
      if (home) {
        rc = home;
      }
#else
      #error Unknown platform
#endif
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string Utils::UserName()
    {
      string  rc;
#if (defined(__unix__) || defined(unix) || defined(__unix)) || defined(__APPLE__)
      int    buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
      if (buflen > 0) {
        //  Use password entry for user ID
        char  *buf = (char *)malloc(buflen);
        if (buf) {
          struct passwd  pwd, *result = nullptr;
          if (getpwuid_r(getuid(), &pwd, buf, buflen, &result) == 0) {
            rc = pwd.pw_name;
          }
          free(buf);
        }
      }
      else {
        //  Use environment
        char  *userName = getenv("USER");
        if (userName) {
          rc = userName;
        }
      }
#elif defined(_WIN32)
      //  Use environment
      char  *userName = getenv("USERNAME");
      if (userName) {
        rc = userName;
      }
#else
      #error Unknown platform
#endif
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    string Utils::HostName()
    {
      string  rc;
      char    hname[256] = {0};
      if (gethostname(hname, 256) == 0) {
        rc = hname;
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    bool Utils::ScalarMult(const std::string & sk, const std::string & pk,
                           std::string & q)
    {
      bool     rc = false;
      uint8_t  qbuf[crypto_scalarmult_BYTES];
      if (crypto_scalarmult(qbuf, (const uint8_t *)sk.data(),
                            (const uint8_t *)pk.data()) == 0) {
        q.assign((const char *)qbuf, sizeof(qbuf));
        rc = true;
      }
      else {
        q.clear();
      }
      return rc;
    }

    //------------------------------------------------------------------------
    //!  
    //------------------------------------------------------------------------
    std::string
    Utils::EndPointString(const boost::asio::ip::tcp::endpoint & endPoint)
    {
      return (endPoint.address().to_string() + ':'
              + std::to_string(endPoint.port()));
    }

  }  // namespace Credence

}  // namespace Dwm
