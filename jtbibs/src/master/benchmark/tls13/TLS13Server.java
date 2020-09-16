
package master.benchmark.tls13;

import demo.DemoUtil;
import demo.ecc.ECCDemoUtil;
import iaik.security.ssl.*;
import master.AServer;
import master.ECCommon;

import java.io.OutputStream;

import static master.HibeCommon.sDebug;


public class TLS13Server extends AServer {
  /**
   * port number to listen on
   */
  final static int PORT = 4432;


  /**
   * Configures and runs the server.
   */
  public TLS13Server() throws Exception {

    DemoUtil.initDemos();
    boolean eccAvailable = false;
    try {
      ECCDemoUtil.installIaikEccProvider();
      eccAvailable = true;
    } catch (Exception e) {
      // ignore; ECC not available
      System.err.println("ECC not possible to add!"); // MINE
      e.printStackTrace();
    }
    
    
    // the server context
    SSLServerContext serverContext = new SSLServerContext();
    
    // set the server certificates (in this demo we want to accept any client certificate)
    boolean setRootCaAsTrustAnchor = false;
    if (eccAvailable) {
      ECCDemoUtil.setServerCertificates(serverContext, setRootCaAsTrustAnchor);
    } else {
      DemoUtil.setServerCertificates(serverContext);
    }
    ECCommon.getInstance(TLS13Client.sCurve).addServerCertificates(serverContext);

    // request client authentication
    // serverContext.setRequestClientCertificate(true);
    // accept clients without certificate as well
    serverContext.addTrustedCertificate(null);

    serverContext.setAllowedProtocolVersions(SSLContext.VERSION_TLS12, SSLContext.VERSION_TLS13);
    
    // enabled all default ciphersuites
    serverContext.setEnabledCipherSuiteList(new CipherSuiteList(CipherSuiteList.L_DEFAULT));

    // set some extensions
    setExtensions(serverContext);
  
    serverContext.updateCipherSuites();

    if (!sDebug)
      serverContext.setDebugStream((OutputStream) null);
    else
      serverContext.setDebugStream(System.out);
    // display configuration
    if (sDebug)
      System.out.println("ServerContext:\n" + serverContext);

    serverContext_ = serverContext;
    port_ = PORT;
  }

  /**
   * Configures the given SSLContext with some extensions required
   * for TLS 1.3.
   * If not explicitly set the required extensions will be calcualted
   * and set automatically.
   * 
   * @param context the (server) context to be configured
   */
  public static void setExtensions(SSLServerContext context) throws Exception {
    
    // the extension list
    ExtensionList extensions = new ExtensionList();
    
    // server_name  
    ServerNameList serverNameList = new ServerNameList();
    extensions.addExtension(serverNameList);
    
    // supported_groups (default list)
    //SupportedGroups supportedGroups = new SupportedGroups();
    
    // enable some specific groups only
    NamedGroup[] namedGroups = { 
        SupportedGroups.NC_PRIME_SECP256R1,
        SupportedGroups.NC_X25519,
        SupportedGroups.FFDHE_2048
    };
    SupportedGroups supportedGroups = new SupportedGroups(namedGroups, true);
    extensions.addExtension(supportedGroups);

    // key_share
    KeyShare keyShare = KeyShare.createKeyShare(supportedGroups);
    extensions.addExtension(keyShare);
    
    // psk_key_exchange_modes
    PskKeyExchangeModes pskModes = new PskKeyExchangeModes(PskKeyExchangeModes.PSK_DHE_KE);
    extensions.addExtension(pskModes);
    
    // signature_algorithms
    SignatureScheme[] algorithms = {
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ed25519,
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.rsa_pkcs1_sha1,
      };
    SignatureAlgorithms signatureAlgorithms = 
      new SignatureAlgorithms(new SignatureSchemeList(algorithms));
    extensions.addExtension(signatureAlgorithms);
    
    // signature_algorithms_cert
    SignatureAlgorithms signatureAlgorithmsCert = 
      new SignatureAlgorithmsCert(new SignatureSchemeList(algorithms));
    extensions.addExtension(signatureAlgorithmsCert);
    
    extensions.setAllCritical(false);
  
    // enable extensions
    context.setExtensions(extensions);
  }
  
 
  
  /**
   * Main method.
   */
  public static void main(String args[]) {
    try {
      TLS13Server tlsServer = new TLS13Server();
      tlsServer.start();
    } catch( Throwable e ) {
      System.err.println("An error occured:");
      e.printStackTrace(System.err);
    }
  } 
  
  
}
