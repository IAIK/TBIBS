package master;

import demo.DemoUtil;
import demo.ecc.ECCDemoUtil;
import iaik.security.hibe.HIBEProvider;
import iaik.security.ssl.*;
import master.iaikProviderImpl.IaikHibeProvider;

import java.io.OutputStream;
import java.security.Security;

import static master.HibeCommon.sDebug;


public class MasterServer extends AServer {
  /**
   * port number to listen on
   */
  final static int PORT = 4433;


  /**
   * Configures and runs the server.
   */
  public MasterServer() throws Exception{

    DemoUtil.initDemos();
    boolean eccAvailable = false;
    try {
      ECCDemoUtil.installIaikEccProvider();
      eccAvailable = true;
    } catch (Exception e) {
      // ignore; ECC not available
      System.err.println("ERROR: ECC not available!");
    }
    Security.addProvider(new HIBEProvider());
    SecurityProvider.setSecurityProvider(new IaikHibeProvider());

    //REAL START

    // the server context
    SSLServerContext serverContext = new SSLServerContext();

    // set the server certificates (in this demo we want to accept any client certificate)
    boolean setRootCaAsTrustAnchor = false;
    if (eccAvailable) {
      ECCDemoUtil.setServerCertificates(serverContext, setRootCaAsTrustAnchor);
    } else {
      DemoUtil.setServerCertificates(serverContext);
    }
    HibeCommon.getInstance().addServerCertificates(serverContext);

    // request client authentication
    // serverContext.setRequestClientCertificate(true);
    // accept clients without certificate as well
    serverContext.addTrustedCertificate(null);

    serverContext.setAllowedProtocolVersions(SSLContext.VERSION_TLS13, SSLContext.VERSION_TLS13);

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

    // create and run the server
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
        SupportedGroups.HIBE,
        SupportedGroups.NC_PRIME_SECP256R1,
        SupportedGroups.NC_X25519,
        SupportedGroups.FFDHE_2048
    };
    SupportedGroups supportedGroups = new SupportedGroups(namedGroups, true);
    extensions.addExtension(supportedGroups);

    // key_share
    NamedGroup[] keyshareNGroups = {
        SupportedGroups.NC_PRIME_SECP256R1,
        SupportedGroups.NC_X25519,
        SupportedGroups.FFDHE_2048
    };
    SupportedGroups keyshareGroups = new SupportedGroups(keyshareNGroups, true);
    KeyShare keyShare = KeyShare.createKeyShare(keyshareGroups);
    extensions.addExtension(keyShare);

    // psk_key_exchange_modes
    PskKeyExchangeModes pskModes = new PskKeyExchangeModes(PskKeyExchangeModes.PSK_DHE_KE);
    extensions.addExtension(pskModes);

    // signature_algorithms
    SignatureScheme[] algorithms = {
        SignatureScheme.hibe,
        SignatureScheme.rsa_pkcs1_sha1
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
      MasterServer ms = new MasterServer();
      ms.start();
    } catch (Throwable e) {
      System.err.println("An error occured:");
      e.printStackTrace(System.err);
    }
  }


}
