import Entities.*;
import HIBE.Hibe;
import iaik.security.ec.math.curve.AtePairingOverBarretoNaehrigCurveFactory;
import iaik.security.ec.math.curve.Pairing;
import iaik.security.ec.math.curve.PairingTypes;
import iaik.security.ec.math.field.ExtensionFieldElement;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;


public class UnitsTests {
  private static Logger logger = Logger.getLogger(UnitsTests.class);

  @Rule
  public TestName name = new TestName();

  @Before
  public void before() {

  }

  @Test
  public void samePairingTest() {
    final int field_size = 256;
    final String mCurve = "BN_P256";
    final Pairing pairing1 = AtePairingOverBarretoNaehrigCurveFactory
        .getPairing(PairingTypes.TYPE_3, mCurve);
    final Pairing pairing2 = AtePairingOverBarretoNaehrigCurveFactory
        .getPairing(PairingTypes.TYPE_3, mCurve);

    Assert.assertEquals(pairing1.getGroup1(), pairing2.getGroup1());
    Assert.assertEquals(pairing1.getGroup2(), pairing2.getGroup2());
    Assert.assertEquals(pairing1.getTargetGroup(), pairing2.getTargetGroup());
  }

  @Test
  public void samePairingGTest() {
    final int field_size = 256;
    final String mCurve = "BN_P256";
    final Pairing pairing1 = AtePairingOverBarretoNaehrigCurveFactory
        .getPairing(PairingTypes.TYPE_3, mCurve);
    final Pairing pairing2 = AtePairingOverBarretoNaehrigCurveFactory
        .getPairing(PairingTypes.TYPE_3, mCurve);

    Assert.assertEquals(pairing1.getGroup1().getGenerator(), pairing2.getGroup1().getGenerator()); //TODO this might be a problem
    Assert.assertEquals(pairing1.getGroup2().getGenerator(), pairing2.getGroup2().getGenerator()); //TODO this might be a problem
    // TODO not needed as public parameter, other paramters could be even derived by random oracle
  }


  @Test
  public void hashTest() {

    for (int i = 0; i < 100; i++) {
      final Pairing pairing = AtePairingOverBarretoNaehrigCurveFactory.getPairing(PairingTypes.TYPE_3,
          "BN_P256");
      BigInteger p = pairing.getGroup1().getOrder();
      PublicParams pp = new PublicParams(p, null, null, null, null, null, null, null, null, 0);
      byte[] randomBytes = new byte[1024];
      new Random().nextBytes(randomBytes);
      BigInteger bi = pp.hash(randomBytes);
      Assert.assertTrue("wrong length", p.bitLength() >= bi.bitLength()); //FIXME: sometimes this fails
      Assert.assertTrue("bigger than p", p.compareTo(bi) > 0);
    }
  }

  @Test
  public void manyDelegations() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(3, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());
    DelegatedSecretKey delSecKey2 = hibeWebserver.delegation(pp, delSecKey, "19-12-2019_12:12:12".getBytes());

    //CDN
    Hibe hibeCDN = new Hibe();
    DelegatedSecretKey delSecKey3 = hibeCDN.delegation(pp, delSecKey2, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();
    //naor
    ChipherText ct = hibeClient.encrypt(mkp.pubKey, gt, pp);
    ExtensionFieldElement m = hibeClient.decrypt(pp, delSecKey3, ct);
    Assert.assertEquals(m, gt);

    Assert.assertTrue(hibeClient.ntProbVerify(pp, mkp.pubKey, delSecKey3));
    Assert.assertTrue(hibeClient.ntDeterVerify(pp, mkp.pubKey, delSecKey3));
  }

  @Test
  public void wantToVerifyMoreIDs() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(3, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());
    pp.addID("19-12-2019_12:12:12".getBytes());
    pp.addID("I am a message that wants to be signed, bla balbal balbalbal".getBytes());

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();
    //naor
    ChipherText ct = hibeClient.encrypt(mkp.pubKey, gt, pp);
    ExtensionFieldElement m = hibeClient.decrypt(pp, delSecKey, ct);
    Assert.assertNotEquals(m, gt);

    Assert.assertFalse(hibeClient.ntProbVerify(pp, mkp.pubKey, delSecKey));
    Assert.assertFalse(hibeClient.ntDeterVerify(pp, mkp.pubKey, delSecKey));
  }
  @Test
  public void wantToVerifyLessIDs() {
    // Webserver
    Hibe hibe = new Hibe();
    PublicParams pp = hibe.setUp(3, new SecurityParams());
    MasterKeyPair mkp = hibe.keyGen(pp);
    DelegatedSecretKey delSecKey = hibe.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());
    DelegatedSecretKey delSecKey2 = hibe.delegation(pp, delSecKey, "19-12-2019_12:12:12".getBytes());
    DelegatedSecretKey delSecKey3 = hibe.delegation(pp, delSecKey2, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());

    //encrypt using two IDs
    pp.ID.remove(2);
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();
    ChipherText ct = hibe.encrypt(mkp.pubKey, gt, pp);

    //decrypt using twice delegated
    pp.addID("I am a message that wants to be signed, bla balbal balbalbal".getBytes());
    ExtensionFieldElement m = hibe.decrypt(pp, delSecKey2, ct);
    Assert.assertEquals(m, gt);

    //decrypted using 3times delegated
    ExtensionFieldElement m1 = hibe.decrypt(pp, delSecKey3, ct);
    Assert.assertNotEquals(m1, gt);
  }

  @Test
  public void twoDelegations() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(2, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());

    //CDN
    Hibe hibeCDN = new Hibe();
    DelegatedSecretKey delSecKey3 = hibeCDN.delegation(pp, delSecKey, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();
    //naor
    ChipherText ct = hibeClient.encrypt(mkp.pubKey, gt, pp);
    ExtensionFieldElement m = hibeClient.decrypt(pp, delSecKey3, ct);
    Assert.assertEquals(m, gt);

    Assert.assertTrue(hibeClient.ntProbVerify(pp, mkp.pubKey, delSecKey3));
    Assert.assertTrue(hibeClient.ntDeterVerify(pp, mkp.pubKey, delSecKey3));
  }

  @Test
  public void wrongTextTest() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(3, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());
    DelegatedSecretKey delSecKey2 = hibeWebserver.delegation(pp, delSecKey, "19-12-2019_12:12:12".getBytes());

    //CDN
    Hibe hibeCDN = new Hibe();
    DelegatedSecretKey delSecKey3 = hibeCDN.delegation(pp, delSecKey2, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();

    //evil
    pp.ID.remove(2);
    pp.ID.add("evil devil".getBytes());

    //naor
    ChipherText ct = hibeClient.encrypt(mkp.pubKey, gt, pp);
    ExtensionFieldElement m = hibeClient.decrypt(pp, delSecKey3, ct);
    Assert.assertNotEquals(m, gt);

    Assert.assertFalse(hibeClient.ntProbVerify(pp, mkp.pubKey, delSecKey3));
    Assert.assertFalse(hibeClient.ntDeterVerify(pp, mkp.pubKey, delSecKey3));
  }

  @Test
  public void tooManyDeleg() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(2, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());
    DelegatedSecretKey delSecKey2 = hibeWebserver.delegation(pp, delSecKey, "19-12-2019_12:12:12".getBytes());

    try {
      //CDN
      Hibe hibeCDN = new Hibe();
      DelegatedSecretKey delSecKey3 = hibeCDN.delegation(pp, delSecKey2, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());
    } catch (AssertionError e) {
      logger.error(e.getMessage());
      return;
    }
    Assert.fail("Not stopping when too many delegations");
  }

  @Test
  public void zeroDelegAllowed() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(0, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);


    try {
      //CDN
      Hibe hibeCDN = new Hibe();
      DelegatedSecretKey delSecKey3 = hibeCDN.delegation(pp, mkp.secKey, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());
    } catch (AssertionError e) {
      logger.error(e.getMessage());
      return;
    }
    Assert.fail("Not stopping when too many delegations");
  }

  @Test
  public void oneDeleg() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(1, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);

    //one delegation
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();
    //naor
    ChipherText ct = hibeClient.encrypt(mkp.pubKey, gt, pp);
    ExtensionFieldElement m = hibeClient.decrypt(pp, delSecKey, ct);
    Assert.assertEquals(m, gt);

    Assert.assertTrue(hibeClient.ntProbVerify(pp, mkp.pubKey, delSecKey));
    Assert.assertTrue(hibeClient.ntDeterVerify(pp, mkp.pubKey, delSecKey));
  }

  @Test
  public void withoutDeleg() {
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(3, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp.GT.getUniformlyRandomNonZeroElement();
    //naor
    DelegatedSecretKey key = new DelegatedSecretKey(mkp.secKey.clone(), pp.G2.getNeutralPoint().clone(), new ArrayList<>(), 0);
    ChipherText ct = hibeClient.encrypt(mkp.pubKey, gt, pp);
    ExtensionFieldElement m = hibeClient.decrypt(pp, key, ct);
    Assert.assertEquals(m, gt);

    Assert.assertTrue(hibeClient.ntProbVerify(pp, mkp.pubKey, key));
    Assert.assertTrue(hibeClient.ntDeterVerify(pp, mkp.pubKey, key));
  }

  @Test
  public void notSameKeys() {
    Hibe hibe1 = new Hibe();
    PublicParams pp1 = hibe1.setUp(3, new SecurityParams());
    MasterKeyPair mkp1 = hibe1.keyGen(pp1);

    Hibe hibe2 = new Hibe();
    PublicParams pp2 = hibe2.setUp(3, new SecurityParams());
    MasterKeyPair mkp2 = hibe2.keyGen(pp2);

    Assert.assertNotEquals(mkp1.secKey, mkp2.secKey);
    Assert.assertNotEquals(mkp1.pubKey, mkp2.pubKey);

    Hibe hibeClient = new Hibe();
    ExtensionFieldElement gt = pp1.GT.getUniformlyRandomNonZeroElement();
    //naor
    ChipherText ct = hibeClient.encrypt(mkp1.pubKey, gt, pp1);
    DelegatedSecretKey key = new DelegatedSecretKey(mkp2.secKey.clone(), pp2.G2.getNeutralPoint().clone(), new ArrayList<>(), 0);
    ExtensionFieldElement m = hibeClient.decrypt(pp2, key, ct);
    Assert.assertNotEquals(gt, m);
  }
}
