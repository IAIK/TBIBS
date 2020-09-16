import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;


import Entities.SecurityParams;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.KeyBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.hibe.HIBEAlgorithmParameterSpec;
import iaik.security.hibe.HIBEDelPrivKey;
import iaik.security.hibe.HIBEKeyPairParamSpec;
import iaik.security.hibe.HIBEProvider;
import iaik.security.provider.IAIK;
import iaik.utils.PemOutputStream;
import iaik.x509.X509Certificate;
import master.HibeDemoUtils;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class HIBECertificateTest {
  private static Logger logger = Logger.getLogger(HIBECertificateTest.class);

  @Before
  public void init() {
    IAIK.addAsProvider();
    ECCelerate.addAsProvider();
    Security.addProvider(new HIBEProvider());
  }

  @Test
  public void StoreASimpleCert() {
    try {
      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(1, new SecurityParams());
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("HIBE");
      kpg.initialize(params);
      KeyPair kp = kpg.generateKeyPair();

      final X509Certificate cert = HibeDemoUtils.createCertSelfSigned(kp);

      // create a new PKCS12 object
      final PKCS12 testWrite = HibeDemoUtils.createPKCS12(cert, kp);
      final File file = new File(HibeDemoUtils.FILENAME);
      file.deleteOnExit();

      final OutputStream os = new FileOutputStream(file);
      try {
        testWrite.writeTo(os);
      } finally {
        try {
          os.close();
        } catch (final IOException e) {
          logger.error("could not write to File correctly\n" + e.getMessage());
        }
      }

      // parse the PKCS#12 object
      logger.info("Parsing PKCS#12 object...");

      final InputStream is = new FileInputStream(file);
      PKCS12 pkcs12;
      try {
        pkcs12 = new PKCS12(is);
      } finally {
        try {
          is.close();
        } catch (final IOException e) {
          // ignore
        }
      }

      logger.info("Verifying MAC...");
      // verify the MAC
      if (!pkcs12.verify(HibeDemoUtils.PASSWORD)) {
        throw new PKCSException("Verification error!");
      }

      // decrypt the PKCS#12 object
      logger.info("Decrypting PKCS#12 object...");
      pkcs12.decrypt(HibeDemoUtils.PASSWORD);

      // get the private key
      final KeyBag keyBag = pkcs12.getKeyBag();
      final PrivateKey privateKey = keyBag.getPrivateKey();

      logger.info("The key is an " + privateKey.getAlgorithm() + " key");
      System.out.println();

      // get the certificates
      final CertificateBag[] certBag = pkcs12.getCertificateBags();

      logger.info("Certificate : ");
      logger.info(certBag[0].getCertificate());
      logger.info("DONE!");

    } catch (CertificateException | PKCSException | InvalidKeyException | NoSuchAlgorithmException | IOException | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      Assert.fail("Exception!");
    }
  }

  @Test
  public void CreateCSR() {
    KeyPairGenerator kpg = null;
    try {
      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(1, new SecurityParams());
      kpg = KeyPairGenerator.getInstance("HIBE");
      kpg.initialize(params);
      KeyPair kp = kpg.generateKeyPair();

      // create a new Name
      Name subject = new Name();
      subject.addRDN(ObjectID.country, "AT");
      subject.addRDN(ObjectID.locality, "Graz");
      subject.addRDN(ObjectID.organization, "TU Graz");
      subject.addRDN(ObjectID.organizationalUnit, "IAIK");
      subject.addRDN(ObjectID.commonName, "PKCS#10 Test");

      // new CertificateRequest
      CertificateRequest request = new CertificateRequest(kp.getPublic(),
          subject);
      // sign the request
      request.sign(HIBEProvider.HIBE_ALG, kp.getPrivate()); //TODO
      logger.info("Request generated:");
      logger.info(request);
      System.out.println();
      // write the DER encoded Request to an OutputStream
      FileOutputStream fos = new FileOutputStream("csrBase64.csr");
      PemOutputStream pem = new PemOutputStream(fos,
          "-----BEGIN CERTIFICATE REQUEST-----",
          "-----END CERTIFICATE REQUEST-----");
      request.writeTo(pem);
      pem.close();
      fos.close();

      //Test at: https://ssl-trust.com/SSL-Zertifikate/csr-decoder
    } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testCertChain() {
    try {

      byte[] delData = "02.02.2020".getBytes();
      byte[] signData = "Data to be signed.".getBytes();

      KeyPairGenerator ca_kpg = KeyPairGenerator.getInstance("RSA");
      ca_kpg.initialize(1024);
      KeyPair ca_kp = ca_kpg.generateKeyPair();

      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(2, new SecurityParams());
      KeyPairGenerator server_kpg = KeyPairGenerator.getInstance("HIBE");
      server_kpg.initialize(params);
      KeyPair server_kp = server_kpg.generateKeyPair();

      final X509Certificate caCert = HibeDemoUtils.createCaCert(ca_kp);
      final X509Certificate serverCert = HibeDemoUtils.createServerCert(ca_kp.getPrivate(), server_kp.getPublic());

      // create a new PKCS12 object for CA
      final PKCS12 ca_Pkcs12 = HibeDemoUtils.createPKCS12(caCert, ca_kp);
      final File caFile = new File("Ca" + HibeDemoUtils.FILENAME);
      caFile.deleteOnExit();

      final OutputStream os = new FileOutputStream(caFile);
      try {
        ca_Pkcs12.writeTo(os);
      } catch (IOException e) {
        e.printStackTrace();
      } finally {
        try {
          os.close();
        } catch (final IOException e) {
          logger.error("could not write to File correctly\n" + e.getMessage());
        }
      }

      // create a new PKCS12 object for Server
      final PKCS12 server_Pkcs12 = HibeDemoUtils.createPKCS12(serverCert, server_kp);
      final File serFile = new File("Server" + HibeDemoUtils.FILENAME);
      serFile.deleteOnExit();

      final OutputStream os2 = new FileOutputStream(serFile);
      try {
        server_Pkcs12.writeTo(os2);
      } catch (IOException e) {
        e.printStackTrace();
      } finally {
        try {
          os2.close();
        } catch (final IOException e) {
          logger.error("could not write to File correctly\n" + e.getMessage());
        }
      }

      Signature sig = Signature.getInstance("HIBE");
      //Server: delegate signing
      sig.initSign(server_kp.getPrivate());
      sig.update(delData);
      byte[] signature = sig.sign();
      HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature);
      //CDN: sign signing!
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData));
      sig.initSign(delPrivKey);
      sig.update(signData);
      byte[] signature2 = sig.sign();

      //Client
      // parse the PKCS#12 object server
      logger.info("Parsing PKCS#12 object...");
      final InputStream ser_is = new FileInputStream(serFile);
      PKCS12 serPkcs12 = new PKCS12(ser_is);
      logger.info("Verifying MAC...");
      if (!serPkcs12.verify(HibeDemoUtils.PASSWORD)) {
        throw new PKCSException("Verification error!");
      }
      logger.info("Decrypting PKCS#12 object...");
      serPkcs12.decrypt(HibeDemoUtils.PASSWORD);
      final CertificateBag[] serCertBag = serPkcs12.getCertificateBags();
      X509Certificate serCert = serCertBag[0].getCertificate();

      // parse the PKCS#12 object ca //TODO pem without priv Key
      logger.info("Parsing PKCS#12 object...");
      final InputStream ca_is = new FileInputStream(caFile);
      PKCS12 caPkcs12 = new PKCS12(ca_is);
      logger.info("Verifying MAC...");
      if (!caPkcs12.verify(HibeDemoUtils.PASSWORD)) {
        throw new PKCSException("Verification error!");
      }
      logger.info("Decrypting PKCS#12 object...");
      caPkcs12.decrypt(HibeDemoUtils.PASSWORD);
      final CertificateBag[] caCertBag = caPkcs12.getCertificateBags();
      X509Certificate ca2Cert = caCertBag[0].getCertificate();

      //Client: verify
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData));
      sig.initVerify(serCert);
      sig.update(signData);
      boolean isValid = sig.verify(signature2);

      if (isValid) { //test certificate
        logger.info("HIBE Signature valid");
        logger.info("Verifying server cert ...");
        serCert.verify(ca2Cert.getPublicKey());
        logger.info("Verifying CA cert ...");
        ca2Cert.verify(ca2Cert.getPublicKey());
      }

      if (isValid)
        logger.info("Demo Done! Signature verified!");
      else
        Assert.fail("Signature is fake!");

    } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | PKCSException | SignatureException | IOException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      Assert.fail("Exception!");
    }
  }

}
