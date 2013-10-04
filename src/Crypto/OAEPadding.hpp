#ifndef DISSENT_CRYPTO_OAEPADDING_H_GUARD
#define DISSENT_CRYPTO_OAEPADDING_H_GUARD

#include <QByteArray>
#include <QString>

#include "CryptoRandom.hpp"

namespace Dissent {
namespace Crypto {

class OAEPadding {
public:
  /**
   * gives the minimum padding length
   */
  static int MinimumPaddingLength();

  /**
   * pad a string using given padding length
   * returns Null string if padding length is too small
   */
  static QByteArray Pad(const QByteArray &data, int paddingLength);

  /**
   * unpad a string, returns Null string if the string is invalid
   */
  static QByteArray UnPad(const QByteArray &data);
};

} /* Crypto */
} /* Dissent */

#endif
