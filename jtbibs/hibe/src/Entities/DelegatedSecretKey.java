package Entities;

import iaik.security.ec.math.curve.ECPoint;

import java.util.List;

public class DelegatedSecretKey {

  public final ECPoint a0;
  public final ECPoint a1;
  public final List<ECPoint> b;
  public int depth = 0;

  /**
  params need to be cloned
   */
  public DelegatedSecretKey(ECPoint cloned_a0, ECPoint cloned_a1, List<ECPoint> cloned_b, int depth) {
    this.a0 = cloned_a0;
    this.a1 = cloned_a1;
    this.b = cloned_b;
    this.depth = depth;
  }

  public ECPoint get_b_k() {
    return b.get(0);
  }

}
