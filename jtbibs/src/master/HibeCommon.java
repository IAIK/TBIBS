package master;

import Entities.SecurityParams;
import iaik.security.hibe.*;
import iaik.security.ssl.SSLClientContext;
import iaik.security.ssl.SSLServerContext;
import iaik.x509.X509Certificate;

import java.security.*;


import org.apache.log4j.Logger;

public class HibeCommon {
  private static Logger logger = Logger.getLogger(HibeCommon.class);

  enum TlsDemoMode {
    Normal,
    MissingDelegate
  }

  public static boolean sDebug = true;

  private X509Certificate mCaCert;
  private KeyPair mCaKp;
  private X509Certificate mSvCert;
  private KeyPair mSvKp;
  private PrivateKey mCDNprivK;


  private static HibeCommon mInstance = null;

  public static HibeCommon getInstance() {
    return getInstance(TlsDemoMode.Normal);
  }
  public static HibeCommon getInstance(TlsDemoMode mode) {
    if (mInstance == null) {
      synchronized (HibeCommon.class) {
        if (mInstance == null) {
          mInstance = new HibeCommon(mode);
        }
      }
    }
    return mInstance;
  }

  private HibeCommon(TlsDemoMode mode) {
    System.out.println("common");
    init();

    try {

      KeyPairGenerator ca_kpg = KeyPairGenerator.getInstance("RSA");
      ca_kpg.initialize(1024);
      mCaKp = ca_kpg.generateKeyPair();

      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(3, new SecurityParams());
      KeyPairGenerator server_kpg = KeyPairGenerator.getInstance("HIBE");
      server_kpg.initialize(params);
      mSvKp = server_kpg.generateKeyPair();
      mCDNprivK = mSvKp.getPrivate();

      mCaCert = HibeDemoUtils.createCaCert(mCaKp);
      mSvCert = HibeDemoUtils.createServerCert(mCaKp.getPrivate(), mSvKp.getPublic());

      if (!mode.equals(TlsDemoMode.MissingDelegate)) {
          byte[] domain = HibeDemoUtils.SERVER_NAME.getBytes();
        byte[] epoch = HIBEUtils.getEpoch(HIBEUtils.EpochGranularity.Day);
        // Server
        Signature sig = Signature.getInstance("HIBE");
        sig.initSign(mSvKp.getPrivate());
        sig.update(domain);
        byte[] signature = sig.sign();
        HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature); //TODO find solution to stay in JSA
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(domain));
        sig.initSign(delPrivKey);
        sig.update(epoch);
        byte[] signature2 = sig.sign();
        //CDN
        mCDNprivK = new HIBEDelPrivKey(signature2);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private void init() {
//    IAIK.addAsProvider();
//    ECCelerate.addAsProvider();
    Security.addProvider(new HIBEProvider());
  }

  public void addClientCertificates(SSLClientContext context) {
  logger.info("adding own cert");
    // ADD OWN CERTIFICATES Chain
    context.addTrustedCertificate(mCaCert);
  }
  public void addServerCertificates(SSLServerContext context) {
    logger.info("adding own cert");
    // ADD OWN CERTIFICATES Chain
    context.addServerCredentials(new java.security.cert.X509Certificate[]{mSvCert, mCaCert}, mCDNprivK);
  }

}
