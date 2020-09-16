package HIBE;

import Entities.*;
import iaik.security.ec.common.SecurityStrength;
import iaik.security.ec.math.curve.*;
import iaik.security.ec.math.field.ExtensionField;
import iaik.security.ec.math.field.ExtensionFieldElement;
import org.apache.log4j.Logger;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;


public class Hibe implements IHIBE {
  private static Logger logger = Logger.getLogger(Hibe.class);

  public enum Curve {
    BN_P256,
    BN_P461,
    BN_P638,
    ISO_P512
  }

  public static Curve sCurve = Curve.BN_P256;

  private final int mFieldSize;

  private final Pairing mPairing;

  private final SecureRandom mRandom;

  public Hibe() {
    System.out.println("HIBE Bits of Security: " + sCurve);
      if (sCurve.equals(Curve.BN_P461)) {
        mFieldSize = 461;
        mPairing = AtePairingOverBarretoNaehrigCurveFactory
            .getPairing(PairingTypes.TYPE_3, 461);
      } else if (sCurve.equals(Curve.BN_P638)) {
        mFieldSize = 638;
        mPairing = AtePairingOverBarretoNaehrigCurveFactory
            .getPairing(PairingTypes.TYPE_3, "BN_P638");
      } else if (sCurve.equals(Curve.ISO_P512)) {
        mFieldSize = 512;
        mPairing = AtePairingOverBarretoNaehrigCurveFactory
            .getPairing(PairingTypes.TYPE_3,"ISO_P512");
      } else {
        mFieldSize = 256;
        mPairing = AtePairingOverBarretoNaehrigCurveFactory
            .getPairing(PairingTypes.TYPE_3,"BN_P256");
      }

    mRandom = SecurityStrength
        .getSecureRandom(SecurityStrength.getSecurityStrength(mFieldSize));
  }

  @Override
  public PublicParams setUp(int max_hibe_height, SecurityParams securities) {
    EllipticCurve G1 = mPairing.getGroup1();
    EllipticCurve G2 = mPairing.getGroup2();
    ExtensionField GT = mPairing.getTargetGroup();

    ECPoint g = G1.getGenerator();
    ECPoint g_head = G2.getGenerator();

    //ECPoint g2 = MyUtils.getPoint(G1, random); // TODO better?
    ECPoint g2 = MyUtils.rejectionSampling(G1);
    ECPoint g3 = MyUtils.rejectionSampling(G1);
    List<ECPoint> h = new ArrayList<>();
    for (int i = 0; i < max_hibe_height; i++) { //<= cuz k < l, k can be max max_hibe_height - 1
      h.add(MyUtils.rejectionSampling(G1));
    }
    BigInteger p = mPairing.getGroup1().getOrder();


    return new PublicParams(p, G1, G2, GT, g, g_head, g2, g3, h, max_hibe_height);
  }


  @Override
  public MasterKeyPair keyGen(PublicParams pp) {
    final BigInteger alpha = new BigInteger(pp.p.bitLength() - 1, mRandom);

    //g_head^alpha, g_2^alpha
    return new MasterKeyPair(pp.g_head.multiplyPoint(alpha), pp.g2.multiplyPoint(alpha));
  }

  @Override
  public DelegatedSecretKey delegation(PublicParams pp, ECPoint master_sec_key, byte[] id) {
    logger.debug("first delegation");
    int depth = 0;
    assert pp.max_hibe_height > depth : "Further delegations are not allowed";
    pp.addID(id);
    assert pp.ID.size() - 1 == depth;
    final BigInteger v = new BigInteger(pp.p.bitLength() - 1, mRandom);

    // Part 1
    //h_1^H(I_1)...h_k^H(I_k)
    ECPoint hibeProduct = pp.h.get(depth).clone().multiplyPoint(pp.hash(pp.ID.get(depth))); // cuz k = 0

    //(hibeProduct * g_3)^v
    ECPoint inner = hibeProduct.clone().addPoint(pp.g3)
        .multiplyPoint(v);

    //g_2^alpha * inner
    ECPoint part1 = inner.clone().addPoint(master_sec_key);

    // Part 2
    //g_head^v
    ECPoint part2 = pp.g_head.clone().multiplyPoint(v);

    // Part 3
    //h_k+1^v,...,h_l^v
    List<ECPoint> part3 = new ArrayList();
    List<ECPoint> h = new ArrayList<>();

    h = pp.h.subList(depth + 1, pp.h.size()); //leave out first
    if (h.size() == 0)
      logger.info("last delegate, no h sublist left");

    for (ECPoint hi : h) {
      part3.add(hi.clone().multiplyPoint(v));
    }

    assert (part3.size() == pp.h.size() - 1);

    return new DelegatedSecretKey(part1, part2, part3, depth + 1);
  }

  @Override
  public DelegatedSecretKey delegation(PublicParams pp, DelegatedSecretKey del_key, byte[] id) {
    logger.debug("another delegation");
    assert pp.max_hibe_height > del_key.depth : "Further delegations are not allowed";
    pp.addID(id);
    assert pp.ID.size() - 1 == del_key.depth;
    final BigInteger w = new BigInteger(pp.p.bitLength() - 1, mRandom);

    // Part 1
    //h_1^H(I_1)...h_k^H(I_k)
    ECPoint hibeProduct = pp.h.get(0).clone().multiplyPoint(pp.hash(pp.ID.get(0)));
    for (int i = 1; i <= del_key.depth; i++) { // cuz del_key.depth+1 = k
      ECPoint additive = pp.h.get(i).clone().multiplyPoint(pp.hash(pp.ID.get(i)));
      hibeProduct.addPoint(additive);
    }

    //(hibeProduct * g_3)^w
    ECPoint inner = hibeProduct.clone().addPoint(pp.g3)
        .multiplyPoint(w);

    //a_0 * b_k^H(I_k) * inner
    ECPoint part1 = del_key.a0.clone()
        .addPoint(del_key.get_b_k().clone()
            .multiplyPoint(pp.hash(pp.ID.get(del_key.depth))))
        .addPoint(inner);

    // Part 2
    //a_1 * g_head^w
    ECPoint part2 = del_key.a1.clone().addPoint(pp.g_head.clone().multiplyPoint(w));

    // Part 3
    //b_k+1 * h_k+1^w,...,b_l * h_l^w
    List<ECPoint> part3 = new ArrayList<>();

    List<ECPoint> b = del_key.b.subList(1, del_key.b.size()); // first left out (k+1) cuz only k elements
    List<ECPoint> h = pp.h.subList(del_key.depth + 1, pp.h.size()); // k+1
    assert (h.size() == b.size());
    if (h.size() == 0)
      logger.info("last delegate, no h sublist left");

    for (int i = 0; i < h.size(); i++) { // cuz sublist start with element k+1
      part3.add(b.get(i).clone().addPoint(h.get(i).clone().multiplyPoint(w)));
    }
    assert (part3.size() == del_key.b.size() - 1);

    return new DelegatedSecretKey(part1, part2, part3, del_key.depth + 1);
  }

  @Override
  public ChipherText encrypt(ECPoint pubK, ExtensionFieldElement msg_gt, PublicParams pp) {
    logger.debug("encryption");
    final BigInteger s = new BigInteger(pp.p.bitLength() - 1, mRandom);

    //id' <- (H(I_1),...,H(I_k)) e Z_p*^k, k<l
    List<BigInteger> HI = new ArrayList<>();
    for (int i = 0; i < pp.ID.size(); i++) {
      HI.add(pp.hash(pp.ID.get(i)));
    }

    // Part 1
    //e(g_2, pk)^s * M
    ExtensionFieldElement part1 = mPairing.pair(pp.g2, pubK) // now in Target group
        .exponentiate(s)
        .multiply(msg_gt);

    // Part 2
    //g_head^s
    ECPoint part2 = pp.g_head.clone().multiplyPoint(s);

    // Part 3
    //(h_1^îd'[1]*...*h_k^id'[k] * g_3)^s
    ECPoint part3;
    if (pp.ID.size() > 0) {
      part3 = pp.h.get(0).clone().multiplyPoint(HI.get(0));
      for (int i = 1; i < pp.ID.size(); i++) {
        part3.addPoint(pp.h.get(i).clone().multiplyPoint(HI.get(i)));
      }
      part3 = part3.clone().addPoint(pp.g3)
          .multiplyPoint(s);
    } else {
      part3 = pp.g3.clone().multiplyPoint(s);
    }

    return new ChipherText(part1, part2, part3);
  }

  @Override
  public ExtensionFieldElement decrypt(PublicParams pp, DelegatedSecretKey del_key, ChipherText ct) {
    logger.debug("decryption");
//    final BigInteger w = new BigInteger(pp.p.bitLength() - 1, mRandom);

    //Den ersten und zweiten Teil brauchst du nur wenn del_key nicht für die passende Identität abgeleitet war
//    // Part 1
//    // (a0 * (h_1^H(I_1)*...*h_k^H(I_k) * g3)^w
//    List<BigInteger> HI = new ArrayList<>();
//    for (int i = 0; i < del_key.depth; i++) {
//      HI.add(pp.hash(pp.ID.get(i).getBytes()));
//    }
//    ECPoint prod = pp.h.get(0).clone().multiplyPoint(HI.get(0));
//    for (int i = 1; i < del_key.depth; i++) {
//      prod.addPoint(pp.h.get(i).clone().multiplyPoint(HI.get(i)));
//    }
//    ECPoint a0 = del_key.a0.clone()
//        .addPoint(prod)
//        .addPoint(pp.g3)
//        .multiplyPoint(w);
//
//    // Part 2
//    //a1 * g_head^w
//    ECPoint a1 = del_key.a1.clone().addPoint(pp.g_head.multiplyPoint(w));

    // Finally
    // M <- C1 * e(C3, a1) * e(a0, C2)^-1
    //                     * e(a0^-1, C2) -> same
    return ct.c1.multiply(mPairing.pairProduct(new ECPoint[]{ct.c3, del_key.a0.clone().negatePoint()}, new ECPoint[]{del_key.a1, ct.c2}));
//    return ct.c1.multiply(mPairing.pair(ct.c3, del_key.a1)).multiply(mPairing.pair(del_key.a0.negatePoint(), ct.c2));

  }

  @Override
  public boolean ntProbVerify(PublicParams pp, ECPoint pubKey, DelegatedSecretKey delSecKey) {
    ExtensionFieldElement gt = getPairing().getTargetGroup().getUniformlyRandomNonZeroElement();
    ChipherText ct = encrypt(pubKey, gt, pp);
    ExtensionFieldElement m = decrypt(pp, delSecKey, ct);
    return m.equals(gt);
  }

  @Override
  public boolean ntDeterVerify(PublicParams pp, ECPoint pubKey, DelegatedSecretKey dsk) { //optimized
    logger.info("entering deterministic verify");
    // e(h1^H(id1)*...*hl^H(idl), sk2) * e(g2, pk) = e(sk1, g_head) ... sk1 = a0, sk2 = a1 ... b = []
    List<BigInteger> Hi = new ArrayList<>();
    for (int i = 0; i < pp.ID.size(); i++) {
      Hi.add(pp.hash(pp.ID.get(i)));
    }

    ECPoint h_multi = pp.g3.clone();
    if (!Hi.isEmpty())
      h_multi.addPoint(mPairing.getGroup1().multiplySimultaneously(Hi.toArray(new BigInteger[]{}), pp.h.toArray(new ECPoint[]{})));


    logger.info("verifying...");
    return mPairing.pairProduct(new ECPoint[]{h_multi, pp.g2, dsk.a0.clone().negatePoint()}, new ECPoint[]{dsk.a1, pubKey, pp.g_head}).isOne();
  }

  public Pairing getPairing() {
    return mPairing;
  }
}
