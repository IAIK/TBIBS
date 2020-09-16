package master;

import demo.DemoUtil;
import demo.ecc.ECCDemoUtil;
import iaik.security.ssl.*;

import java.io.OutputStream;
import java.security.Security;

import iaik.security.hibe.HIBEProvider;
import master.iaikProviderImpl.IaikHibeProvider;
import org.apache.log4j.Logger;

import static master.HibeCommon.sDebug;


/**
 * Client part of the TLS 1.3 demo.
 * For running this demo first start the {@link MasterServer TLS13Server}
 * to listen for TLS connections on localhost, port 4433. Then run
 * the client.
 * Make sure that the demo keystore (<code>isasilkecc.keystore</code>,
 * created with {@link demo.ecc.SetupEccKeyStore SetupEccKeyStore}, if
 * IAIK-ECCelerate<sup>TM</sup> is in the classpath, or
 * <code>isasilk.keystore</code>) is located in your current working directory.
 * <p>
 * For using ECC you need the IAIK-ECCelerate<sup>TM</sup> library. You can
 * get it from <a href = "https://jce.iaik.tugraz.at/sic/Products/Core_Crypto_Toolkits/ECCelerate">
 * https://jce.iaik.tugraz.at/sic/Products/Core_Crypto_Toolkits/ECCelerate</a>.
 *
 * @see MasterServer
 */
public class MasterClient extends AClient{

  private static Logger logger = Logger.getLogger(MasterClient.class);


  /**
   * Connects to the demo TLS13Server listening on localhost, port 4433
   * and establishes a TLS connection using TLS extensions.
   */
  @Override
  public void setup(String arg[]) throws Exception {

    String serverName = "DEMO-SERVER";
    int serverPort = 4433;

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
    Security.addProvider(new HIBEProvider());
    SecurityProvider.setSecurityProvider(new IaikHibeProvider());

    // client context
    SSLClientContext context = new SSLClientContext();

    // add certificates for client authentication (in this demo we want to accept any server certificate)
    boolean setRootCaAsTrustAnchor = false;
    if (eccAvailable) {
      ECCDemoUtil.setClientCertificates(context, setRootCaAsTrustAnchor);
    } else {
      DemoUtil.setClientCertificates(context, setRootCaAsTrustAnchor);
    }
    HibeCommon.getInstance().addClientCertificates(context);

    // verify OCSP responses got from the server
    context.setChainVerifier(new OCSPCertStatusChainVerifier());


    context.setAllowedProtocolVersions(SSLContext.VERSION_TLS13, SSLContext.VERSION_TLS13); //MINE only TLS 1.3 allowed

    // enabled all default ciphersuites
    context.setEnabledCipherSuiteList(new CipherSuiteList(CipherSuiteList.L_DEFAULT));

    // set some TLS extensions
    setExtensions(context);

    context.updateCipherSuites();

    ///// OWN /////////////
    //no Session Resumption
    context.getSessionManager().setResumePeriod(0);
    //no Renegotiaton
    context.setDisableRenegotiation(true);
    if (!sDebug)
      context.setDebugStream((OutputStream) null);
    else
      context.setDebugStream(System.out);

    // dump context
    if (sDebug) {
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
   *
   * @param context the (server) context to be configured
   */
  public void setExtensions(SSLClientContext context)
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
        SupportedGroups.HIBE, //TODO should not be necessary??
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
      MasterClient mc = new MasterClient();
      mc.setup(args);
      mc.connect();
    } catch (Throwable e) {
      System.err.println("An error occured:");
      e.printStackTrace(System.err);
    }
    DemoUtil.waitKey();
  }


}
