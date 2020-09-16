package Entities;

import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.curve.EllipticCurve;
import iaik.security.ec.math.field.*;

import java.math.BigInteger;
import java.util.Random;

public class MyUtils {

  public static ECPoint rejectionSampling(EllipticCurve G) {
    AbstractPrimeField field = (AbstractPrimeField) G.getField();
    ECPoint g2 = null;
    while (g2 == null) {
      PrimeFieldElement x = field.getUniformlyRandomNonZeroElement();
      g2 = G.getPoint(x);
    }
    return g2;
  }

  public static ECPoint getPoint(final EllipticCurve curve, final Random random) {
    ECPoint p;
    final Field field = (Field) curve.getField();

    do {
      final FieldElement x = field.newElement(new BigInteger(field.getFieldSize() - 1, random));
      p = curve.getPoint(x);
    } while (p == null);

    System.out.println("Created point " + p);

    return p;
  }
}
