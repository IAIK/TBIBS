

package master.benchmark.tls13;

import demo.DemoUtil;
import demo.ecc.ECCDemoUtil;
import iaik.security.ssl.*;
import master.AClient;
import master.ECCommon;
import master.HibeCommon;
import org.apache.log4j.Logger;

import java.io.OutputStream;

import static master.HibeCommon.sDebug;


public class TLS13Client extends AClient {
  private static Logger logger = Logger.getLogger(TLS13Client.class);

  public enum SignAlgo { //TODO find better place Demo util eg?
    Ed25519,
    EcDsa,
    RSA
  }

  public static SignAlgo sCurve = SignAlgo.Ed25519;

  /**
   * Connects to the demo TLS13Server listening on localhost, port 4433
   * and establishes a TLS connection using TLS extensions.
   */
  @Override
  public void setup(String arg[]) throws Exception {

    String serverName = "DEMO-SERVER";
    int serverPort = 4432;

    if (arg.length >= 1) {              // server name
      serverName = arg[0];
    }

    int p = serverName.indexOf(':');   // server port
    if (p > 0) {
      serverPort = Integer.decode(serverName.substring(p + 1)).intValue();
      serverName = serverName.substring(0, p);
    }

    DemoUtil.initDemos();
    boolean eccAvailable = false;
    try {
      ECCDemoUtil.installIaikEccProvider();
      eccAvailable = true;
    } catch (Exception e) {
      logger.error("ECC not possible to add!");
      e.printStackTrace();
    }


    // client context
    SSLClientContext context = new SSLClientContext();

    // add certificates for client authentication (in this demo we want to accept any server certificate)
//    boolean setRootCaAsTrustAnchor = false;
//    if (eccAvailable) {
//      ECCDemoUtil.setClientCertificates(context, setRootCaAsTrustAnchor);
//    } else {
//      DemoUtil.setClientCertificates(context, setRootCaAsTrustAnchor);
//    }

    // verify OCSP responses got from the server
    ChainVerifier chainVerifier = new OCSPCertStatusChainVerifier();
    ECCommon.getInstance(sCurve).addClientCertificates(chainVerifier);
    context.setChainVerifier(chainVerifier);


    context.setAllowedProtocolVersions(SSLContext.VERSION_TLS13, SSLContext.VERSION_TLS13);

    // enabled all default ciphersuites
    context.setEnabledCipherSuiteList(new CipherSuiteList(CipherSuiteList.L_DEFAULT));

    // set some TLS extensions
    setExtensions(context);

    context.updateCipherSuites();

    /////////// OWN /////////////////
    //no Session Resumption
    context.getSessionManager().setResumePeriod(0);
    //no Renegotiaton
    context.setDisableRenegotiation(true);
    // no debug
    if (!sDebug)
      context.setDebugStream((OutputStream) null);
    else
      context.setDebugStream(System.out);
    if (sDebug) {
      // dump context
      System.out.println("Context:\n" + context);
      System.out.println();
    }

    this.serverName = serverName;
    this.serverPort = serverPort;
    this.context = context;
  }

  /**
   * Configures the given SSLContext with some extensions required
   * for TLS 1.3.
   * If not explicitly set the required extensions will be calcualted
   * and set automatically.
   */
  private void setExtensions(SSLClientContext context)
      throws Exception {

    // the extension list
    ExtensionList extensions = new ExtensionList();

    // server_name
    ServerNameList serverNames = new ServerNameList();
    extensions.addExtension(serverNames);

    // server_name  
    ServerNameList serverNameList = new ServerNameList();
    extensions.addExtension(serverNameList);

    // supported_groups (default list)
    //SupportedGroups supportedGroups = new SupportedGroups();

    // enable some specific groups only
    NamedGroup[] namedGroups = {
        SupportedGroups.NC_PRIME_SECP256R1,
        SupportedGroups.NC_X25519,
        SupportedGroups.FFDHE_2048,
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
    SignatureScheme[] algorithms = new SignatureScheme[]{SignatureScheme.ed25519, SignatureScheme.rsa_pkcs1_sha1};
    if (sCurve.equals(SignAlgo.Ed25519)) {
      algorithms = new SignatureScheme[]{SignatureScheme.ed25519, SignatureScheme.rsa_pkcs1_sha1};
    } else if (sCurve.equals(SignAlgo.EcDsa)) {
      algorithms = new SignatureScheme[]{SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.rsa_pkcs1_sha1};
    } else if (sCurve.equals(SignAlgo.RSA)) {
      algorithms = new SignatureScheme[]{SignatureScheme.rsa_pkcs1_sha256, SignatureScheme.rsa_pkcs1_sha1};
    }

    SignatureAlgorithms signatureAlgorithms =
        new SignatureAlgorithms(new SignatureSchemeList(algorithms));
    extensions.addExtension(signatureAlgorithms);

    // signature_algorithms_cert
    SignatureAlgorithms signatureAlgorithmsCert =
        new SignatureAlgorithmsCert(new SignatureSchemeList(algorithms));
    extensions.addExtension(signatureAlgorithmsCert);

    // certificate_status_request
    CertificateStatusRequest certStatusRequest = new CertificateStatusRequest();
    extensions.addExtension(certStatusRequest);

    extensions.setAllCritical(false);

    // enable extensions
    context.setExtensions(extensions);

  }

  /**
   * Main Method.
   */
  public static void main(String args[]) {
    try {
      TLS13Client tc = new TLS13Client();
      tc.setup(args);
      tc.connect();
    } catch (Throwable e) {
      System.err.println("An error occured:");
      e.printStackTrace(System.err);
    }
    DemoUtil.waitKey();
  }


}
