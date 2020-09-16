package Entities;

import iaik.security.ec.math.curve.ECPoint;

public class MasterKeyPair {
  public final ECPoint pubKey;
  public final ECPoint secKey;

  public MasterKeyPair(ECPoint pubKey, ECPoint secKey) {

    this.pubKey = pubKey;
    this.secKey = secKey;
  }
}
