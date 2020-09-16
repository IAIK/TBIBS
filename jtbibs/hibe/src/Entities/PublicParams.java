package Entities;

import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.curve.EllipticCurve;
import iaik.security.ec.math.field.ExtensionField;
//import iaik.security.hibe.HibeParameterSpec;
import iaik.security.md.SHA256;
import org.apache.log4j.Logger;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PublicParams implements IPublicParams {
  private static Logger logger = Logger.getLogger(PublicParams.class);


  public final BigInteger p;
  public final EllipticCurve G1;
  public final EllipticCurve G2;
  public final ExtensionField GT;
  public final ECPoint g;
  public final ECPoint g_head;
  public final ECPoint g2;
  public final ECPoint g3;
  public final List<ECPoint> h;
  public int max_hibe_height;
  public final List<byte[]> ID;

  public PublicParams(BigInteger p, EllipticCurve G1, EllipticCurve G2, ExtensionField GT, ECPoint g, ECPoint g_head,
                      ECPoint g2, ECPoint g3, List<ECPoint> h, int max_hibe_height) {
    this.p = p;
    this.G1 = G1;
    this.G2 = G2;
    this.GT = GT;
    this.g = g;
    this.g_head = g_head;
    this.g2 = g2;
    this.g3 = g3;
    this.h = h;
    this.max_hibe_height = max_hibe_height;
    this.ID = new ArrayList<>();
  }

  /**
   * Rejection sampling for length(p) == 256
   *
   * @param msg
   * @return 256 bits long integer
   */
  @Override
  public BigInteger hash(byte[] msg) {
    SHA256 sha = new SHA256();
    byte[] h = sha.digest(msg);
    logger.debug("#bits p: " + p.bitLength());
    logger.debug("#bits h: " + new BigInteger(1, h).bitLength());
    while (new BigInteger(1, h).compareTo(this.p) >= 0) {
      logger.debug("rehashing");
      sha.reset();
      h = sha.digest(h);
      logger.debug("#bits h: " + new BigInteger(1, h).bitLength());
    }
    return new BigInteger(1, h);
  }

  public void addID(byte[] id) {
    this.ID.add(id);
  }
}
