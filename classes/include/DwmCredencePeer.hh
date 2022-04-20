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
    //!  Identity authentication is optional but highly recommended, as I
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
      //!  Used by a server to accept a new connection.  Returns true on
      //!  success, false on failure.  Note that @c s is expected to be
      //!  a socket that was already accepted
      //!  (via Boost::asio::ip::tcp::acceptor::accept()).
      //----------------------------------------------------------------------
      bool Accept(boost::asio::ip::tcp::socket && s);
      
      //----------------------------------------------------------------------
      //!  Used by a client to connect to @c host at the given @c port.
      //!  Returns true on success, false on failure.
      //----------------------------------------------------------------------
      bool Connect(const std::string & host, uint16_t port);

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
      //!  a Dwm::StreamIO::Write(ostream &, const T &) function or
      //!  implement the Dwm::StreamWritable interface (see
      //!  DwmStreamIOCapable.hh in libDwm).
      //----------------------------------------------------------------------
      template <typename T>
      bool Send(const T & msg)
      {
        bool  rc = false;
        if (_xos) {
          if (StreamIO::Write(*_xos, msg)) {
            if (_xos->flush()) {
              rc = true;
            }
            else {
              Syslog(LOG_ERR, "Failed to flush encrypted stream to %s",
                     EndPointString().c_str());
            }
          }
          else {
            Syslog(LOG_ERR, "Failed to send message to %s",
                   EndPointString().c_str());
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
      //!  Dwm::StreamIO::Read(istream &, T &) function or implement the
      //!  Dwm::StreamReadable interface (see DwmStreamIOCapable.hh in
      //!  libDwm).
      //----------------------------------------------------------------------
      template <typename T>
      bool Receive(T & msg)
      {
        bool  rc = false;
        if (_xis) {
          if (StreamIO::Read(*_xis, msg)) {
            rc = true;
          }
          else {
            Syslog(LOG_ERR, "Failed to receive message from %s",
                   EndPointString().c_str());
          }
        }
        else {
          Syslog(LOG_ERR, "Invalid encrypted input stream");
        }
        return rc;
      }

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
      std::string                                      _theirId;
      std::string                                      _agreedKey;
      std::unique_ptr<boost::asio::ip::tcp::iostream>  _ios;
      std::unique_ptr<XChaCha20Poly1305::Istream>      _xis;
      std::unique_ptr<XChaCha20Poly1305::Ostream>      _xos;

    };
    
  }  // namespace Credence

}  // namespace Dwm

#endif  // _DWMCREDENCEPEER_HH_
