#include <QDebug>
#include <QNetworkInterface>
#include <QScopedPointer>
#include "SslEdgeListener.hpp"

namespace Dissent {
namespace Transports {
  const QString SslEdgeListener::Scheme = "ssl/tls";

  void SslServer::incomingConnection(int socketDescriptor)
  {
    QSslSocket *socket = new QSslSocket(this);
    if (socket->setSocketDescriptor(socketDescriptor)) {
      // TODO: add certificates
      QObject::connect(socket, SIGNAL(encrypted()), this, SLOT(connectionEncrypted()));
      socket->startServerEncryption();
    } else {
      delete socket;
    }
  }

  void SslServer::connectionEncrypted() {
    QSslSocket *socket = qobject_cast<QSslSocket *>(QObject::sender());
    if (socket) {
      newConnection(socket);
    }
  }

  SslEdgeListener::SslEdgeListener(const TcpAddress &local_address) :
    TcpEdgeListener(local_address)
  {
  }

  EdgeListener *SslEdgeListener::Create(const Address &local_address)
  {
    const TcpAddress &ta = static_cast<const TcpAddress &>(local_address);
    return new SslEdgeListener(ta);
  }

  SslEdgeListener::~SslEdgeListener()
  {
    DestructorCheck();
  }

  void SslEdgeListener::OnStart()
  {
    EdgeListener::OnStart();

    const TcpAddress &addr = static_cast<const TcpAddress &>(GetAddress());

    if(!_server.listen(addr.GetIP(), addr.GetPort())) {
      qFatal("%s", QString("Unable to bind to " + addr.ToString()).toUtf8().data());
    }

    QObject::connect(&_server, SIGNAL(newConnection(QSslSocket *)),
                     this, SLOT(HandleAccept(QSslSocket *)));

    // XXX the following is a hack so I don't need to support multiple local addresses
    QHostAddress ip = _server.serverAddress();
    if(ip == QHostAddress::Any) {
      ip = QHostAddress::LocalHost;
      foreach(const QHostAddress &local_ip, QNetworkInterface::allAddresses()) {
        if(local_ip == QHostAddress::Null ||
            local_ip == QHostAddress::LocalHost ||
            local_ip == QHostAddress::LocalHostIPv6 ||
            local_ip == QHostAddress::Broadcast ||
            local_ip == QHostAddress::Any ||
            local_ip == QHostAddress::AnyIPv6)
        {
            continue;
        }
        ip = local_ip;
        break;
      }
    }

    int port = _server.serverPort();
    SetAddress(TcpAddress(ip.toString(), port));
  }

  void SslEdgeListener::OnStop()
  {
    EdgeListener::OnStop();
    _server.close();
    foreach(QSslSocket *socket, _outstanding_sockets.keys()) {
      HandleSocketClose(socket, "EdgeListner Stopped");
    }
    _outstanding_sockets.clear();
  }

  void SslEdgeListener::HandleAccept(QSslSocket *socket)
  {
    AddSocket(socket, false);
  }

  void SslEdgeListener::CreateEdgeTo(const Address &to)
  {
    if(Stopped()) {
      qWarning() << "Cannot CreateEdgeTo Stopped EL";
      return;
    }

    if(!Started()) {
      qWarning() << "Cannot CreateEdgeTo non-Started EL";
      return;
    }

    qDebug() << "Connecting to" << to.ToString();
    QSslSocket *socket = new QSslSocket(this);

    QObject::connect(socket, SIGNAL(connected()), this, SLOT(HandleConnect()));
    QObject::connect(socket, SIGNAL(disconnected()), this, SLOT(HandleDisconnect()));
    QObject::connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
        this, SLOT(HandleError(QAbstractSocket::SocketError)));

    const TcpAddress &rem_ta = static_cast<const TcpAddress &>(to);
    _outstanding_sockets.insert(socket, rem_ta);
    socket->connectToHost(rem_ta.GetIP(), rem_ta.GetPort());
  }

  void SslEdgeListener::HandleConnect()
  {
    QSslSocket *socket = qobject_cast<QSslSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleConnect signal received a non-socket";
      return;
    }

    QObject::disconnect(socket, SIGNAL(connected()), this, SLOT(HandleConnect()));
    QObject::connect(socket, SIGNAL(encrypted()), this, SLOT(HandleEncrypt()));

    socket->startClientEncryption();
  }

  void SslEdgeListener::HandleEncrypt()
  {
    QSslSocket *socket = qobject_cast<QSslSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleEncrypt signal received a non-socket";
      return;
    }

    QObject::disconnect(socket, SIGNAL(encrypted()), this, SLOT(HandleEncrypt()));
    QObject::disconnect(socket, SIGNAL(disconnected()), this, SLOT(HandleDisconnect()));
    QObject::disconnect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
        this, SLOT(HandleError(QAbstractSocket::SocketError)));
    _outstanding_sockets.remove(socket);
    AddSocket(socket, true);
  }

  void SslEdgeListener::HandleDisconnect()
  {
    QSslSocket *socket = qobject_cast<QSslSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleDisconnect signal received a non-socket";
      return;
    }
    HandleSocketClose(socket, "Disconnected");
  }

  void SslEdgeListener::HandleError(QAbstractSocket::SocketError)
  {
    QSslSocket *socket = qobject_cast<QSslSocket *>(sender());
    if(socket == 0) {
      qCritical() << "HandleError signal received a non-socket";
      return;
    }
    HandleSocketClose(socket, socket->errorString());
  }

  void SslEdgeListener::HandleSocketClose(QSslSocket *socket, const QString &reason)
  {
    if(_outstanding_sockets.contains(socket) == 0) {
      return;
    }

    Address addr = _outstanding_sockets.value(socket);
    _outstanding_sockets.remove(socket);

    qDebug() << "Unable to connect to host: " << addr.ToString() << reason;

    socket->deleteLater();
    ProcessEdgeCreationFailure(addr, reason);
  }

  void SslEdgeListener::AddSocket(QSslSocket *socket, bool outgoing) {
    TcpAddress remote(socket->peerAddress().toString(), socket->peerPort());

    if(outgoing) {
      qDebug() << "Handling a successful connectTo from" << remote.ToString();
    } else {
      qDebug() << "Incoming connection from" << remote.ToString();
    }

    // After successfully estabilishing a secure connection, QSslSocket can be
    // used as a plain QTcpSocket

    // deleteLater since a socket may potentially be closed during a read operation
    QSharedPointer<Edge> edge(new TcpEdge(GetAddress(), remote, outgoing, socket),
        &QObject::deleteLater);
    SetSharedPointer(edge);
    ProcessNewEdge(edge);
  }
}
}
