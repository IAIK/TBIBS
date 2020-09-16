package master;

import iaik.security.ssl.ChainVerifier;
import iaik.security.ssl.KeyAndCert;
import iaik.security.ssl.SSLServerContext;
import iaik.x509.X509Certificate;
import master.benchmark.tls13.TLS13Client;
import org.apache.log4j.Logger;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static iaik.security.ssl.SSLContext.CERTTYPE_ECDSA_SIGN;
import static iaik.security.ssl.SSLContext.CERTTYPE_RSA_SIGN;
import static master.benchmark.tls13.TLS13Client.sCurve;

public class ECCommon {
  private static Logger logger = Logger.getLogger(ECCommon.class);


  private KeyPair mCaKp;
  private KeyPair mKp;
  private X509Certificate mCaCert;
  private X509Certificate mCDNCert;

  private static ECCommon mInstance = null;
  public static ECCommon getInstance(TLS13Client.SignAlgo algo) {
    if (mInstance == null) {
      synchronized (ECCommon.class) {
        if (mInstance == null) {
          mInstance = new ECCommon(algo);
        }
      }
    }
    return mInstance;
  }

  private ECCommon(TLS13Client.SignAlgo algo) {
    try {
      setupCaKp();

      if (algo.equals(TLS13Client.SignAlgo.Ed25519)) {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        mKp = kpg.generateKeyPair();
      } else if (algo.equals(TLS13Client.SignAlgo.EcDsa)) { //secp256r
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        mKp = kpg.generateKeyPair();
      } else if (algo.equals(TLS13Client.SignAlgo.RSA)){
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        mKp = kpg.generateKeyPair();
      } else assert false;

      mCaCert = HibeDemoUtils.createCaCert(mCaKp);
      mCDNCert = HibeDemoUtils.createServerCert(mCaKp.getPrivate(), mKp.getPublic());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void setupCaKp() throws NoSuchAlgorithmException {
    KeyPairGenerator ca_kpg = KeyPairGenerator.getInstance("RSA");
    ca_kpg.initialize(1024);
    mCaKp = ca_kpg.generateKeyPair();
  }

  private void setupKp(String algo, ECGenParameterSpec ecSpec) throws Exception {

  }



  public void addClientCertificates(ChainVerifier context) {
    logger.info("adding own cert");
    // ADD OWN CERTIFICATES Chain
//    context.clearClientCredentials();
    context.addTrustedCertificate(mCaCert);
  }
  public void addServerCertificates(SSLServerContext context) {
    logger.info("adding own cert");
    // ADD OWN CERTIFICATES Chain
//    context.clearServerCredentials();
    int certtype;
    switch (sCurve){
      case EcDsa: certtype = CERTTYPE_ECDSA_SIGN; break;
      case Ed25519: certtype = CERTTYPE_ECDSA_SIGN; break;
      case RSA: certtype = CERTTYPE_RSA_SIGN;break;
      default: certtype = CERTTYPE_ECDSA_SIGN; assert false;
    }
    context.addServerCredentials(new KeyAndCert(new java.security.cert.X509Certificate[]{mCDNCert, mCaCert}, mKp.getPrivate(), certtype));
  }
}
