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
//!  \file DwmCredencePeer.hh
//!  \author Daniel W. McRobb
//!  \brief Dwm::Credence::Peer class declaration
//---------------------------------------------------------------------------

#ifndef _DWMCREDENCEPEER_HH_
#define _DWMCREDENCEPEER_HH_

#include <chrono>
#include <boost/asio.hpp>

#include "DwmStreamIO.hh"
#include "DwmSysLogger.hh"
#include "DwmCredenceKeyStash.hh"
#include "DwmCredenceKnownKeys.hh"
#include "DwmCredenceXChaCha20Poly1305Istream.hh"
#include "DwmCredenceXChaCha20Poly1305Ostream.hh"

namespace Dwm {

  namespace Credence {

    //------------------------------------------------------------------------
    //!  Encapsulate a network peer.
    //!  Note that once a connection is set up with Accept() or Connect(),
    //!  all traffic will be encrypted with XChacha20Poly1305.
    //!  Identity authentication (via the Authenticate() member function)
    //!  after Accept() or Connect() is optional but highly recommended, as I
    //!  don't have any production code that doesn't use it.
    //------------------------------------------------------------------------
    class Peer
    {
    public:
      //----------------------------------------------------------------------
      //!  Default constructor.
      //----------------------------------------------------------------------
      Peer();

      //----------------------------------------------------------------------
      //!  Sets the time we'll wait for the peer to send its public key.
      //!  If not set, a default of 1000 milliseconds (1 second) will be
      //!  used.
      //----------------------------------------------------------------------
      void SetKeyExchangeTimeout(std::chrono::milliseconds ms);
      
      //----------------------------------------------------------------------
      //!  Used by a server to accept a new connection on the given TCP socket
      //!  @c s.  Returns true on success, false on failure.  Note that @c s
      //!  is expected to be a socket that was already accepted
      //!  (via Boost::asio::ip::tcp::acceptor::accept()).
      //----------------------------------------------------------------------
      bool Accept(boost::asio::ip::tcp::socket && s);

      //----------------------------------------------------------------------
      //!  Used by a server to accept a new connection on the given UNIX
      //!  domain socket @c s.  Returns true on success, false on failure.
      //!  Note that @c s is expected to be a socket that was already accepted
      //!  (via Boost::asio::local::stream_protocol::acceptor::accept()).
      //----------------------------------------------------------------------
      bool Accept(boost::asio::local::stream_protocol::socket && s);
      
      //----------------------------------------------------------------------
      //!  Used by a client to connect to @c host at the given @c port,
      //!  waiting @c timeOut for success.  Returns true on success, false
      //!  on failure.
      //----------------------------------------------------------------------
      bool Connect(const std::string & host, uint16_t port,
                   std::chrono::milliseconds timeOut = std::chrono::milliseconds(5000));

      //----------------------------------------------------------------------
      //!  Used by a client to connect to a UNIX domain socket at the given
      //!  @c path, waiting @c timeOut for success.  Returns true on success,
      //!  false on failure.
      //----------------------------------------------------------------------
      bool Connect(const std::string & path,
                   std::chrono::milliseconds timeOut = std::chrono::milliseconds(5000));
      
      //----------------------------------------------------------------------
      //!  Sets the time we'll wait for the peer to send its ID during
      //!  authentication.  If not set, a default of 1000 milliseconds
      //!  (1 second) will be used.
      //----------------------------------------------------------------------
      void SetIdExchangeTimeout(std::chrono::milliseconds ms);

      //----------------------------------------------------------------------
      //!  Using the given @c keyStash and @c knownKeys, authenticate our
      //!  identity to the peer and verify the peer's identity.  This is
      //!  done using randomly generated challenges which must be signed
      //!  with an Ed25519 key.  Since this should be called immediately
      //!  after Accept() or Connect(), the entire transaction is encrypted
      //!  with XChaCha20Poly1305.
      //!  Returns true on success, false on failure.
      //----------------------------------------------------------------------
      bool Authenticate(const KeyStash & keyStash,
                        const KnownKeys & knownKeys);

      //----------------------------------------------------------------------
      //!  If Authenticate() was used, returns the peer's identifier.
      //----------------------------------------------------------------------
      const std::string & Id() const   { return _theirId; }
      
      //----------------------------------------------------------------------
      //!  Sends the given @c msg to the peer.  Returns true on success,
      //!  false on failure.  Note that T must be supported directly by
      //!  a Dwm::StreamIO::Write() function (see DwmStreamIO.hh in libDwm)
      //!  or meet the requirements of the Dwm::HasStreamWrite concept (see
      //!  DwmStreamIOCapable.hh in libDwm).
      //----------------------------------------------------------------------
      template <typename T>
      requires IsStreamWritable<T>
      bool Send(const T & msg)
      {
        bool  rc = false;
        if (_xos) {
          if (StreamIO::Write(*_xos, msg)) {
            if (_xos->flush()) {
              rc = true;
            }
            else {
              FSyslog(LOG_ERR, "Failed to flush encrypted stream to {}",
                     EndPointString());
            }
          }
          else {
            FSyslog(LOG_ERR, "Failed to send message to {}",
                    EndPointString());
          }
        }
        else {
          Syslog(LOG_ERR, "Invalid encrypted output stream");
        }
        return rc;
      }
      
      //----------------------------------------------------------------------
      //!  Receives the given @c msg from the peer.  Returns true on success,
      //!  false on failure.  Note that T must be supported directly by a
      //!  Dwm::StreamIO::Read() function (See DwmStreamIO.hh in libDwm) or
      //!  meet the requirements of the Dwm::HasStreamRead concept (see
      //!  DwmStreamIOCapable.hh in libDwm).
      //----------------------------------------------------------------------
      template <typename T>
      requires IsStreamReadable<T>
      bool Receive(T & msg)
      {
        bool  rc = false;
        if (_xis) {
          if (StreamIO::Read(*_xis, msg)) {
            rc = true;
          }
          else {
            FSyslog(LOG_DEBUG, "Failed to receive message from {}",
                    EndPointString());
          }
        }
        else {
          Syslog(LOG_ERR, "Invalid encrypted input stream");
        }
        return rc;
      }

      //----------------------------------------------------------------------
      //!  Returns true if a Receive() of @c numBytes or greater would block.
      //----------------------------------------------------------------------
      bool ReceiveWouldBlock(size_t numBytes);
      
      //----------------------------------------------------------------------
      //!  Disconnects the peer.
      //----------------------------------------------------------------------
      void Disconnect();

      //----------------------------------------------------------------------
      //!  Returns a string representation of the peer endpoint, in
      //!  'addr:port' form.
      //----------------------------------------------------------------------
      std::string EndPointString() const;
      
    private:
      std::chrono::milliseconds                        _keyExchangeTimeout;
      std::chrono::milliseconds                        _idExchangeTimeout;
      boost::asio::ip::tcp::endpoint                   _endPoint;
      boost::asio::local::stream_protocol::endpoint    _lendPoint;
      std::string                                      _theirId;
      std::string                                      _agreedKey;
      std::unique_ptr<boost::asio::ip::tcp::iostream>  _ios;
      std::unique_ptr<boost::asio::local::stream_protocol::iostream>  _lios;
      std::unique_ptr<XChaCha20Poly1305::Istream>      _xis;
      std::unique_ptr<XChaCha20Poly1305::Ostream>      _xos;
    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEPEER_HH_
