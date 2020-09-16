import Entities.SecurityParams;
import iaik.security.hibe.*;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class HIBEStandardTest {
  private static Logger logger = Logger.getLogger(HIBEStandardTest.class);


  @Test
  public void WithoutDelegation() {
    Security.addProvider(new HIBEProvider());

    try {

      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(1, new SecurityParams());

      KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
      kg.initialize(params);
      KeyPair kp = kg.generateKeyPair();

      // Factor needed for storing
      KeyFactory kf = KeyFactory.getInstance("HIBE");
      X509EncodedKeySpec x509KeySpec = kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
      // endcode
      byte[] encodedX509KeySpec = x509KeySpec.getEncoded();
      // and back
      X509EncodedKeySpec new_x509KeySpec = new X509EncodedKeySpec(encodedX509KeySpec);
      // regenerate
      PublicKey pubKey = kf.generatePublic(new_x509KeySpec);

      // Factor needed for storing
      PKCS8EncodedKeySpec pkcs8KeySpec = kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);
      // encode
      byte[] encodedPkcs8KeySpec = pkcs8KeySpec.getEncoded();
      // and back
      PKCS8EncodedKeySpec new_pkcs8KeySpec = new PKCS8EncodedKeySpec(encodedPkcs8KeySpec);
      //regenerate
      PrivateKey privKey = kf.generatePrivate(new_pkcs8KeySpec);

      // sign!
      byte[] data = "Data to be signed.".getBytes();
      Signature sig = Signature.getInstance("HIBE");
      sig.initSign(privKey);
      sig.update(data);
      byte[] signature = sig.sign();

      //verify
      sig.initVerify(pubKey);
      sig.update(data);
      boolean isValid = sig.verify(signature);

      if (isValid)
        System.out.println("Demo Done! Signature verified!");
      else
        Assert.fail("Signature is fake!");

    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Exception!");
    }
  }

  @Test
  public void DelegationTest() {
    Security.addProvider(new HIBEProvider());
    byte[] delData = "02.02.2020".getBytes();
    byte[] signData = "Data to be signed.".getBytes();

    try {

      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(2, new SecurityParams());

      KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
      kg.initialize(params);
      KeyPair kp = kg.generateKeyPair();

      Signature sig = Signature.getInstance("HIBE");

      //delegate signing
      sig.initSign(kp.getPrivate());
      sig.update(delData);
      byte[] signature = sig.sign();
      HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature);

      // sign signing!
//      sig = Signature.getInstance("HIBE");
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData));
      sig.initSign(delPrivKey);
      sig.update(signData);
      byte[] signature2 = sig.sign();

      //verify
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData));
      sig.initVerify(kp.getPublic());
      sig.update(signData);
      boolean isValid = sig.verify(signature2);

      if (isValid)
        System.out.println("Demo Done! Signature verified!");
      else
        Assert.fail("Signature is fake!");

    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Exception!");
    }
  }

  @Test
  public void multipleDelegationTest() {
    Security.addProvider(new HIBEProvider());
    byte[] delData1 = "domain".getBytes();
    byte[] delData2 = "02.02.2020".getBytes();
    byte[] signData = "Data to be signed.".getBytes();

    try {

      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(3, new SecurityParams());

      KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
      kg.initialize(params);
      KeyPair kp = kg.generateKeyPair();

      Signature sig = Signature.getInstance("HIBE");

      //delegate signing
      sig.initSign(kp.getPrivate());
      sig.update(delData1);
      byte[] signature1 = sig.sign();
      HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature1);
      //delegate signing
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData1));
      sig.initSign(delPrivKey);
      sig.update(delData2);
      byte[] signature2 = sig.sign();
      HIBEDelPrivKey delPrivKey2 = new HIBEDelPrivKey(signature2);

      // sign signing!
      sig = Signature.getInstance("HIBE");
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData1, delData2));
      sig.initSign(delPrivKey2);
      sig.update(signData);
      byte[] signature3 = sig.sign();

      //verify
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData1, delData2));
      sig.initVerify(kp.getPublic());
      sig.update(signData);
      boolean isValid = sig.verify(signature3);

      if (isValid)
        System.out.println("Demo Done! Signature verified!");
      else
        Assert.fail("Signature is fake!");

    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Exception!");
    }
  }

  @Test
  public void moreDelegationsThanExpected() {
    Security.addProvider(new HIBEProvider());
    byte[] delData1 = "domain".getBytes();
    byte[] delData2 = "02.02.2020".getBytes();
    byte[] signData = "Data to be signed.".getBytes();

    try {

      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(2, new SecurityParams());

      KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
      kg.initialize(params);
      KeyPair kp = kg.generateKeyPair();

      Signature sig = Signature.getInstance("HIBE");

      //delegate signing
      sig.initSign(kp.getPrivate());
      sig.update(delData1);
      byte[] signature1 = sig.sign();
      HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature1);
      //delegate signing
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData1));
      sig.initSign(delPrivKey);
      sig.update(delData2);
      byte[] signature2 = sig.sign();
      HIBEDelPrivKey delPrivKey2 = new HIBEDelPrivKey(signature2);

      // sign signing!
      sig = Signature.getInstance("HIBE");
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData1, delData2));
      sig.initSign(delPrivKey2);
      sig.update(signData);
      byte[] signature3 = sig.sign();

      //verify
      sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData1, delData2));
      sig.initVerify(kp.getPublic());
      sig.update(signData);
      boolean isValid = sig.verify(signature3);

      if (isValid)
        System.out.println("Demo Done! Signature verified!");
      else
        Assert.fail("Signature is fake!");

    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Exception!");
    } catch (AssertionError ae) {
      if (!ae.getMessage().equals("Further delegations are not allowed")) {
        ae.printStackTrace();
        Assert.fail("Exception!");
      } else {
        logger.info(ae.getMessage());
      }
    }
  }

    @Test
    public void WrongVerifyTest () {
      Security.addProvider(new HIBEProvider());
      byte[] delData = "02.02.2020".getBytes();
      byte[] wrongDelData = "02.02.2000".getBytes();
      byte[] signData = "Data to be signed.".getBytes();

      try {

        HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(2, new SecurityParams());

        KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
        kg.initialize(params);
        KeyPair kp = kg.generateKeyPair();

        Signature sig = Signature.getInstance("HIBE");

        //delegate signing
        sig.initSign(kp.getPrivate());
        sig.update(delData);
        byte[] signature = sig.sign();
        HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature);

        // sign signing!
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData));
        sig.initSign(delPrivKey);
        sig.update(signData);
        byte[] signature2 = sig.sign();

        //verify
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(wrongDelData)); //<--here
        sig.initVerify(kp.getPublic());
        sig.update(signData);
        boolean isValid = sig.verify(signature2);

        if (!isValid)
          System.out.println("Demo Done! Signature is fake!");
        else
          Assert.fail("Signature is verified!");

      } catch (Exception e) {
        e.printStackTrace();
        Assert.fail("Exception!");
      }
    }

    @Test
    public void WrongDelegationMsgTest () {
      Security.addProvider(new HIBEProvider());
      byte[] delData = "02.02.2020".getBytes();
      byte[] wrongDelData = "02.02.2000".getBytes();
      byte[] signData = "Data to be signed.".getBytes();

      try {

        HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(2, new SecurityParams());

        KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
        kg.initialize(params);
        KeyPair kp = kg.generateKeyPair();

        Signature sig = Signature.getInstance("HIBE");

        //delegate signing
        sig.initSign(kp.getPrivate());
        sig.update(delData);
        byte[] signature = sig.sign();
        HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(signature);

        // sign signing!
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(wrongDelData)); // <--here
        sig.initSign(delPrivKey);
        sig.update(signData);
        byte[] signature2 = sig.sign();

        //verify
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData));
        sig.initVerify(kp.getPublic());
        sig.update(signData);
        boolean isValid = sig.verify(signature2);

        if (!isValid)
          System.out.println("Demo Done! Signature is fake!");
        else
          Assert.fail("Signature is verified!");

      } catch (Exception e) {
        e.printStackTrace();
        Assert.fail("Exception!");
      }
    }

    @Test
    public void VerifyExpectsMoreDelegations () {
      Security.addProvider(new HIBEProvider());
      byte[] delData = "myserver".getBytes();
      byte[] del2Data = "02.02.2000".getBytes();
      byte[] signData = "Data to be signed.".getBytes();

      try {

        HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.create(1, new SecurityParams());

        KeyPairGenerator kg = KeyPairGenerator.getInstance("HIBE");
        kg.initialize(params);
        KeyPair kp = kg.generateKeyPair();

        Signature sig = Signature.getInstance("HIBE");

        //delegate signing
        sig.initSign(kp.getPrivate());
        sig.update(delData);
        byte[] signature = sig.sign();

        //verify
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(delData, del2Data));
        sig.initVerify(kp.getPublic());
        sig.update(signData);
        boolean isValid = sig.verify(signature);

        if (!isValid)
          System.out.println("Demo Done! Signature is fake!");
        else
          Assert.fail("Signature is verified!");

      } catch (Exception e) {
        if (!e.getMessage().equals("Not correct IDs feeded")) {
          e.printStackTrace();
          Assert.fail("Exception!");
        }
      }
    }

    //TODO test more cases
  }
