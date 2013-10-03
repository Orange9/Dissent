#ifndef DISSENT_CRYPTO_OAEPADDING_H_GUARD
#define DISSENT_CRYPTO_OAEPADDING_H_GUARD

#include <QByteArray>
#include <QString>

#include "CryptoRandom.hpp"

namespace Dissent {
namespace Crypto {

class OAEPadding {
public:
  static int MininumPaddingLength();
  static QByteArray Pad(QByteArray data, int paddingLength);
  static QByteArray UnPad(QByteArray data);
};

} /* Crypto */
} /* Dissent */

#endif
