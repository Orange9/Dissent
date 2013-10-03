#ifndef DISSENT_TRANSPORTS_SSL_EDGE_LISTENER_H_GUARD
#define DISSENT_TRANSPORTS_SSL_EDGE_LISTENER_H_GUARD

#include <QHash>
#include <QObject>
#include <QSharedPointer>
#include <QTcpServer>
#include <QSslSocket>

#include "TcpAddress.hpp"
#include "TcpEdge.hpp"
#include "TcpEdgeListener.hpp"

namespace Dissent {
namespace Transports {
  /**
   * A SSL server that gives QSslSocket instead of QTcpSocket
   */
  class SslServer : public QTcpServer {
    Q_OBJECT

    protected:
      virtual void incomingConnection(int socketDescriptor);

    signals:
      void newConnection(QSslSocket *socket);

    private slots:
      void connectionEncrypted();
  };

  /**
   * Creates edges which can be used to pass messages inside a common process
   */
  class SslEdgeListener : public TcpEdgeListener {
    Q_OBJECT

    public:
      const static QString Scheme;

      explicit SslEdgeListener(const TcpAddress &local_address);
      static EdgeListener *Create(const Address &local_address);

      /**
       * Destructor
       */
      virtual ~SslEdgeListener();

      virtual void CreateEdgeTo(const Address &to);

    protected:
      virtual void OnStart();
      virtual void OnStop();

    private slots:
      void HandleAccept(QSslSocket *socket);
      void HandleConnect();
      void HandleEncrypt();
      void HandleDisconnect();
      void HandleError(QAbstractSocket::SocketError error);
      void HandleSocketClose(QSslSocket *socket, const QString &reason);

    private:
      void AddSocket(QSslSocket *socket, bool outgoing);
      SslServer _server;
      QHash<QSslSocket *, TcpAddress> _outstanding_sockets;
  };
}
}

#endif
