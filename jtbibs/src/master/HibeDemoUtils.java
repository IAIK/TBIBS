package master;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.KeyBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.security.hibe.HIBSProvider;
import iaik.x509.X509Certificate;
import org.apache.log4j.Logger;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.GregorianCalendar;

public class HibeDemoUtils {
  private static Logger logger = Logger.getLogger(HibeDemoUtils.class);

  public static final String SERVER_NAME = "DEMO-SERVER";
  public static final String CDN_NAME = "DEMO-CDN";
  public static final String CA_NAME = "DEMO-CA";

  public static final String TEST_ID = "MyTest ID";
  public static final String FILENAME = "CertTEST.p12";
  public static final byte[] KEY_ID = {0x01, 0x02, 0x03, 0x04};
  public static final char[] PASSWORD = "123456".toCharArray();

  private static Name getName() {
    final Name subject = new Name();
    subject.addRDN(ObjectID.country, "AT");
    subject.addRDN(ObjectID.organization, "TU Graz");
    subject.addRDN(ObjectID.organizationalUnit, "IAIK");
    return subject;
  }

  private static Name getSelfSignedName() {
    final Name subject = getName();
    subject.addRDN(ObjectID.commonName, "IAIK Test Certificate");
    return subject;
  }

  private static Name getCAName() {
    Name subject = getName();
    subject.addRDN(ObjectID.commonName, CA_NAME);
    return subject;
  }

  private static Name getCdnName() {
    Name subject = getName();
    subject.addRDN(ObjectID.commonName, CDN_NAME);
    return subject;
  }
  private static Name getServerName() {
    Name subject = getName();
    subject.addRDN(ObjectID.commonName, SERVER_NAME);
    return subject;
  }

  private static void setValid(X509Certificate cert) {
    final GregorianCalendar date = new GregorianCalendar();
    cert.setValidNotBefore(date.getTime());

    date.add(Calendar.MONTH, 6);
    cert.setValidNotAfter(date.getTime());
  }

  public static X509Certificate createCertSelfSigned(final KeyPair kp)
      throws InvalidKeyException, NoSuchAlgorithmException, CertificateException {

    final X509Certificate cert = new X509Certificate();
    final Name subject = getSelfSignedName();
    cert.setSerialNumber(BigInteger.valueOf(0x1234L));
    cert.setSubjectDN(subject);
    cert.setPublicKey(kp.getPublic());
    cert.setIssuerDN(subject);
    // set the certificate to be valid not before now -> 6 months
    setValid(cert);

    logger.info("Signing selfsigned certificate ..."); //getTBSCertificate
    cert.sign(HIBSProvider.HIBS_ALG, kp.getPrivate());

    return cert;
  }

  public static X509Certificate createCaCert(final KeyPair kp)
      throws InvalidKeyException, NoSuchAlgorithmException, CertificateException {

    final X509Certificate cert = new X509Certificate();
    final Name subject = getCAName();
    cert.setSerialNumber(BigInteger.valueOf(0x1111L));
    cert.setSubjectDN(subject);
    cert.setPublicKey(kp.getPublic());
    cert.setIssuerDN(subject);
    // set the certificate to be valid not before now -> 6 months
    setValid(cert);
    //CA -> self signed
    logger.info("Signing CA certificate ...");
    cert.sign(AlgorithmID.sha1WithRSAEncryption, kp.getPrivate());

    return cert;
  }

  /**
   * https://www.programcreek.com/java-api-examples
   * example 3
   *
   * @param caPk
   * @param serverPubK
   * @return
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws CertificateException
   */
  public static X509Certificate createServerCert(PrivateKey caPk, PublicKey serverPubK)
      throws InvalidKeyException, NoSuchAlgorithmException, CertificateException {

    final X509Certificate cert = new X509Certificate();
    final Name serverSub = getServerName();
    final Name caSub = getCAName();
    cert.setSerialNumber(BigInteger.valueOf(0x4321L));
    cert.setSubjectDN(serverSub);
    cert.setPublicKey(serverPubK);
    cert.setIssuerDN(caSub);
    // set the certificate to be valid not before now -> 6 months
    setValid(cert);
    //server -> Ca sigend
    logger.info("Signing Server certificate ...");
    cert.sign(AlgorithmID.sha1WithRSAEncryption, caPk);

    return cert;
  }

  public static PKCS12 createPKCS12(final X509Certificate cert, final KeyPair kp)
      throws PKCSException {
    final KeyBag keyBag = new KeyBag(kp.getPrivate(), TEST_ID, KEY_ID);
    final CertificateBag certBag = new CertificateBag(cert);
    certBag.setFriendlyName(TEST_ID);
    certBag.setLocalKeyID(KEY_ID);

    final PKCS12 pkcs12 = new PKCS12(keyBag, new CertificateBag[]{certBag}, false);
    pkcs12.encrypt(PASSWORD);

    return pkcs12;
  }
}
