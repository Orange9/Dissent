#ifdef CRYPTOPP

#include "Crypto/Hash.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wtautological-compare"
#include <cryptopp/sha.h>
#pragma GCC diagnostic pop


namespace Dissent {
namespace Crypto {
  class CppHashImpl : public IHashImpl {
    public:
      virtual int GetDigestSize() const
      {
        return m_data.DigestSize();
      }

      virtual void Restart()
      {
        m_data.Restart();
      }

      virtual void Update(const QByteArray &data)
      {
        m_data.Update(reinterpret_cast<const byte *>(
              data.data()), data.size());
      }

      virtual QByteArray ComputeHash()
      {
        QByteArray hash(GetDigestSize(), 0);
        m_data.Final(reinterpret_cast<byte *>(hash.data()));
        return hash;
      }

      virtual QByteArray ComputeHash(const QByteArray &data)
      {
        QByteArray hash(GetDigestSize(), 0);
        m_data.CalculateDigest(reinterpret_cast<byte *>(hash.data()),
            reinterpret_cast<const byte *>(data.constData()),
              data.size());
        return hash;
      }

    private:
      CryptoPP::SHA1 m_data;
  };

  Hash::Hash() : m_data(new CppHashImpl())
  {
  }
}
}

#endif
