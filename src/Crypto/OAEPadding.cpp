#include <QDebug>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wtautological-compare"
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#pragma GCC diagnostic pop

#include "OAEPadding.hpp"

namespace Dissent {
namespace Crypto {

int OAEPadding::MininumPaddingLength()
{
  // more than twice sha-1 digest
  return CryptoPP::SHA1::DIGESTSIZE / 4 + 1;
}

QByteArray OAEPadding::Pad(QByteArray data, int paddingLength)
{
  CryptoPP::OAEP<CryptoPP::SHA1> oaep;

  // use the same PRNG with CryptoRandomImpl.cpp
  CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;

  QByteArray result;
  int len = data.length() + paddingLength;
  result.resize(len);
  oaep.Pad(rng, (const byte *)data.constData(), data.length() * 8,
           (byte *)result.data(), len, CryptoPP::g_nullNameValuePairs);

  return result;
}

QByteArray OAEPadding::UnPad(QByteArray data)
{
  CryptoPP::OAEP<CryptoPP::SHA1> oaep;

  QByteArray result;
  result.resize(data.length());
  CryptoPP::DecodingResult r =
    oaep.Unpad((const byte *)data.constData(), data.length() * 8,
               (byte *)result.data(), CryptoPP::g_nullNameValuePairs);
  if (!r.isValidCoding) {
    result.resize(0);
  } else {
    int len = r.messageLength / 8;
    if (r.messageLength & 0x7) {
      len++;
    }
    result.resize(len);
  }

  return result;
}

}
}
