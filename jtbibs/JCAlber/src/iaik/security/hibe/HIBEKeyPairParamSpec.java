package iaik.security.hibe;

import Entities.PublicParams;
import Entities.SecurityParams;
import HIBE.Hibe;
import iaik.asn1.*;
import iaik.security.ec.errorhandling.DecodingException;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.curve.EllipticCurve;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;


public class HIBEKeyPairParamSpec implements AlgorithmParameterSpec {


  private static final ASN1Object HIBE_PARAMETER_VERSION = new INTEGER(333);

  private final BigInteger p; // prime order

  private final ECPoint g; // from G1
  private final ECPoint g_head; // from G2
  private final ECPoint g2; // from G1
  private final ECPoint g3; // from G1
  private final List<ECPoint> h; // from G1
  private final Hibe mHibe;

  public static HIBEKeyPairParamSpec create(int max_signings, SecurityParams securities) {
    if (securities != null && securities.getCurve() != null) {
      if (securities.getCurve() == null) { //TODO resolve when curve in encoding (two ifs above)
//        Hibe.sCurve = Hibe.Curve.BN_P256;
      } else if (securities.getCurve().equals(HIBEcurve.BN_P461)) {
        Hibe.sCurve = Hibe.Curve.BN_P461;
      } else if (securities.getCurve().equals(HIBEcurve.BN_P638)) {
        Hibe.sCurve = Hibe.Curve.BN_P638;
      } else if (securities.getCurve().equals(HIBEcurve.ISO_P512)) {
        Hibe.sCurve = Hibe.Curve.ISO_P512;
      }
    }

    // TODO error handling? make InvalidAlgorithmParameterException
    Hibe hibe = new Hibe();
    PublicParams pp = hibe.setUp(max_signings, securities);
    return generateToSpec(pp);
  }

  public static HIBEKeyPairParamSpec generateToSpec(PublicParams pp) {
    return new HIBEKeyPairParamSpec(pp.p, pp.g, pp.g_head, pp.g2, pp.g3, pp.h);
  }

  private HIBEKeyPairParamSpec(BigInteger p, ECPoint g, ECPoint g_head, ECPoint g2, ECPoint g3, List<ECPoint> h) {
    this.p = p;
    this.g = g;
    this.g_head = g_head;
    this.g2 = g2;
    this.g3 = g3;
    this.h = h;
    mHibe = new Hibe();
  }

  public ASN1Object toASN1Object() {
    // explicit encoding
    final SEQUENCE s = new SEQUENCE();
    s.addComponent(HIBE_PARAMETER_VERSION);
    s.addComponent(new INTEGER(p));
    s.addComponent(new OCTET_STRING(g.encodePoint()));
    s.addComponent(new OCTET_STRING(g_head.encodePoint()));
    s.addComponent(new OCTET_STRING(g2.encodePoint()));
    s.addComponent(new OCTET_STRING(g3.encodePoint()));

    final SEQUENCE hs = new SEQUENCE();
    for (ECPoint i : h) {
      hs.addComponent(new OCTET_STRING(i.encodePoint()));
    }
    s.addComponent(hs);

    return s;
  }

  public static HIBEKeyPairParamSpec decode(final ASN1Object param) throws InvalidKeyException {
    if (param == null) {
      throw new NullPointerException("HIBE Parameters are null!");
    }


    try {
      final int numberOfComponents = param.countComponents();
      if (numberOfComponents != 7) {
        throw new IllegalArgumentException("Invalid HIBE Domain Parameter Number!");
      }

      final BigInteger parameterVersion = (BigInteger) param.getComponentAt(0).getValue();
      if (!parameterVersion.equals(HIBE_PARAMETER_VERSION.getValue())) {
        throw new IllegalArgumentException("No HIBE Domain Parameter: wrong parameter version!");
      }

      Hibe hibe = new Hibe();
      EllipticCurve G1 = hibe.getPairing().getGroup1();
      EllipticCurve G2 = hibe.getPairing().getGroup2();
      BigInteger p = (BigInteger) param.getComponentAt(1).getValue();
      ECPoint g = G1.decodePoint(((OCTET_STRING) param.getComponentAt(2)).getWholeValue());
      ECPoint g_head = G2.decodePoint(((OCTET_STRING) param.getComponentAt(3)).getWholeValue());
      ECPoint g2 = G1.decodePoint(((OCTET_STRING) param.getComponentAt(4)).getWholeValue());
      ECPoint g3 = G1.decodePoint(((OCTET_STRING) param.getComponentAt(5)).getWholeValue());

      SEQUENCE hs = (SEQUENCE) param.getComponentAt(6);

      List<ECPoint> h = new ArrayList<>();
      for (int i = 0; i < hs.countComponents(); i++) {
        ECPoint e = G1.decodePoint(((OCTET_STRING) hs.getComponentAt(i)).getWholeValue());
        h.add(e);
      }

      return new HIBEKeyPairParamSpec(p, g, g_head, g2, g3, h);
    } catch (IOException e) {
      throw new HIBEInvalidKeyException("Somethings went wrong during IO while reading the HIBE key params!");
    } catch (CodingException | DecodingException e) {
      throw new HIBEInvalidKeyException("Coding/decoding error while reading the HIBE key params!");
    }
  }

  public EllipticCurve getG1() {
    return mHibe.getPairing().getGroup1();
  }

  public EllipticCurve getG2() {
    return mHibe.getPairing().getGroup2();
  }

  public PublicParams getPP() {
    return new PublicParams(p, mHibe.getPairing().getGroup1(), mHibe.getPairing().getGroup2(),
        mHibe.getPairing().getTargetGroup(), g, g_head, g2, g3, h, h.size());
  }
}
