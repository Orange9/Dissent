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

int OAEPadding::MinimumPaddingLength()
{
  // more than twice sha-1 digest
  return CryptoPP::SHA1::DIGESTSIZE * 2 + 1;
}

QByteArray OAEPadding::Pad(const QByteArray &data, int paddingLength)
{
  if (paddingLength < MinimumPaddingLength()) {
    return QByteArray();
  }

  CryptoPP::OAEP<CryptoPP::SHA1> oaep;

  // use the same PRNG with CryptoRandomImpl.cpp
  CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;

  int len = data.length() + paddingLength;
  QByteArray result(len, '\0');
  oaep.Pad(rng, (const byte *)data.constData(), data.length(),
           (byte *)result.data(), len * 8, CryptoPP::g_nullNameValuePairs);

  return result;
}

QByteArray OAEPadding::UnPad(const QByteArray &data)
{
  CryptoPP::OAEP<CryptoPP::SHA1> oaep;

  QByteArray result(data.length(), '\0');
  CryptoPP::DecodingResult r =
    oaep.Unpad((const byte *)data.constData(), data.length() * 8,
               (byte *)result.data(), CryptoPP::g_nullNameValuePairs);
  if (!r.isValidCoding) {
    return QByteArray();
  } else {
    result.resize(r.messageLength);
    return result;
  }
}

}
}
