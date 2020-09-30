package demo;

import Entities.SecurityParams;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.hibe.*;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import java.security.InvalidKeyException;
import java.security.PublicKey;

public class HIBEKeysTest {
  private static Logger logger = Logger.getLogger(HIBEKeysTest.class);

  @Rule
  public TestName mTestName = new TestName();

  @Before
  public void before() {
  }

  @Test
  public void publicKeyTest() {
    logger.info("Executing Test: " + mTestName.getMethodName());

    try {
      HIBSKeyPairParamSpec params = HIBSKeyPairParamSpec.create(2, new SecurityParams());

      ECPoint p = params.getG2().getGenerator();
      HIBSPublicKey pubKey = new HIBSPublicKey(params, p);
      byte[] encoded = pubKey.getEncoded();
      PublicKey pubKey2 = new HIBSPublicKey(encoded);

      Assert.assertEquals(pubKey, pubKey2);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      Assert.fail("en/decoding wrong??");
    }
  }
  @Test
  public void privateKeyTest() {
    logger.info("Executing Test: " + mTestName.getMethodName());

    try {
      HIBSKeyPairParamSpec params = HIBSKeyPairParamSpec.create(2, new SecurityParams());

      ECPoint p = params.getG1().getGenerator();
      HIBSPrivateKey privKey = new HIBSPrivateKey(params, p);
      byte[] encoded = privKey.getEncoded();
      HIBSPrivateKey privKey2 = new HIBSPrivateKey(encoded);

      Assert.assertEquals(privKey, privKey2);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      Assert.fail("en/decoding wrong??");
    }
  }
  @Test
  public void privateDelegatedKeyTest() {
    logger.info("Executing Test: " + mTestName.getMethodName());

    try {
      HIBSKeyPairParamSpec params = HIBSKeyPairParamSpec.create(2, new SecurityParams());

      ECPoint p = params.getG1().getGenerator();
      HIBSPrivateKey privKey = new HIBSPrivateKey(params, p);

      HIBSDelPrivKey delKey = HIBSWithSHA256Signature.delegate(params, privKey, "blaa".getBytes());
      byte[] encoded = delKey.getEncoded();
      HIBSDelPrivKey delKey2 = new HIBSDelPrivKey(encoded);

      Assert.assertEquals(delKey, delKey2);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      Assert.fail("en/decoding wrong??");
    }
  }

}
