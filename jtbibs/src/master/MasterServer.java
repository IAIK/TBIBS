// Copyright (C) 2002 IAIK
// http://jce.iaik.tugraz.at
//
// Copyright (C) 2003 Stiftung Secure Information and 
//                    Communication Technologies SIC
// http://jce.iaik.tugraz.at
//
// All rights reserved.
//
// This source is provided for inspection purposes and recompilation only,
// unless specified differently in a contract with IAIK. This source has to
// be kept in strict confidence and must not be disclosed to any third party
// under any circumstances. Redistribution in source and binary forms, with
// or without modification, are <not> permitted in any case!
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// $Header: /IAIK-SSL/TLS13/TLS13/src/demo/tls13/TLS13Server.java 5     4.10.19 11:04 Dbratko $
//

package master;

import demo.DemoUtil;
import demo.ecc.ECCDemoUtil;
import iaik.security.hibe.HIBSProvider;
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
    Security.addProvider(new HIBSProvider());
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
    serverContext.setRequestClientCertificate(true);
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
