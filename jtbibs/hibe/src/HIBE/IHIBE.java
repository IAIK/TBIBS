package HIBE;

import Entities.*;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.field.ExtensionFieldElement;

import java.util.List;

public interface IHIBE {
  PublicParams setUp(int hibe_height, SecurityParams securities);
  MasterKeyPair keyGen(PublicParams pp);
  DelegatedSecretKey delegation(PublicParams pp, ECPoint master_sec_key, byte[] id);
  DelegatedSecretKey delegation(PublicParams pp, DelegatedSecretKey del_key, byte[] id);
  ChipherText encrypt(ECPoint pubK, ExtensionFieldElement msg_gt, PublicParams pp);
  ExtensionFieldElement decrypt(PublicParams pp, DelegatedSecretKey dkey, ChipherText cipher_text);
  boolean ntProbVerify(PublicParams pp, ECPoint pubKey, DelegatedSecretKey delSecKey3);
  boolean ntDeterVerify(PublicParams pp, ECPoint pubKey, DelegatedSecretKey delSecKey3);
}
