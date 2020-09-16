package master;

import iaik.security.ssl.ExtensionList;
import iaik.security.ssl.SSLClientContext;
import iaik.security.ssl.SSLSocket;
import iaik.security.ssl.Utils;

import java.io.IOException;
import java.security.cert.X509Certificate;

public abstract class AClient {
  protected String serverName;
  protected int serverPort;
  protected SSLClientContext context;
  protected SSLSocket socket;

  public abstract void setup(String arg[]) throws Exception;

  /**
   * Creates a SSLSocket for connecting to the given server.
   * @throws IOException if an error occurs when connecting to the server
   */
  public void connect() throws Exception {
    // connect
    System.out.println("Connect to " + serverName + " on port " + serverPort);
    socket = new SSLSocket(serverName, serverPort, context);
    socket.setSoTimeout(1000 * 3);
    // start handshake
    System.out.println("client handshake started");
    socket.startHandshake();
    System.out.println("client handshake finished");
    socket.close();
  }

  /**
   * Dumps some session parameters.
   * @param socket the SSLSocket
   */
  public void printSessionParameters(SSLSocket socket) {
    // informations about the server:
    System.out.println("TLS Session-Parameter:");
    System.out.println("Active protocol version: " + Utils.versionToName(socket.getActiveProtocolVersion()));
    System.out.println("Active cipher suite: " + socket.getActiveCipherSuite());
    System.out.println("Active compression method: " + socket.getActiveCompressionMethod());
    X509Certificate[] chain = socket.getPeerCertificateChain();
    if (chain != null) {
      System.out.println("Server certificate chain:");
      for (int i = 0; i < chain.length; i++) {
        System.out.println("Certificate " + i + ": " +
            chain[i].getSubjectDN());
      }
    }
    System.out.println();

    ExtensionList peerExtensions = socket.getPeerExtensions();
    System.out.println("Extensions sent by the server: " + ((peerExtensions == null) ? "none" : peerExtensions.toString()));


  }
}
