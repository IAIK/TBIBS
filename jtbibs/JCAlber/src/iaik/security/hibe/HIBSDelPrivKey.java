package iaik.security.hibe;

import Entities.DelegatedSecretKey;
import Entities.PublicParams;
import HIBE.Hibe;
import iaik.asn1.*;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs8.PrivateKeyInfo;
import iaik.security.ec.errorhandling.DecodingException;
import iaik.security.ec.math.curve.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.List;

public class HIBSDelPrivKey extends PrivateKeyInfo {

  private DelegatedSecretKey mKey;
  private transient byte[] encodedDelPrivKey_;

  public static final INTEGER EC_PRIVATE_KEY_VERSION = new INTEGER(334);

  private transient HIBSKeyPairParamSpec params_;

  public HIBSDelPrivKey(HIBSKeyPairParamSpec params, DelegatedSecretKey secKey) {
    if ((params == null) || (secKey == null)) {
      throw new NullPointerException("At least one of params, w is null!");
    } else if (!params.getG1().equals(secKey.a0.getCurve()) &&
        !params.getG2().equals(secKey.a1.getCurve())) {
      throw new IllegalArgumentException("a1 or a2 are not a point on the curve specified by params!");
      //todo also check b
    }
    params_ = params;
    mKey = secKey;
    createHIBEPrivateKey();
  }

  public HIBSDelPrivKey(byte[] endcoded)
      throws InvalidKeyException {
    super(endcoded);
  }

  @Override
  protected void decode(byte[] privateDelKey) throws InvalidKeyException {
    Hibe hibe = new Hibe();
    encodedDelPrivKey_ = privateDelKey;

    final ASN1Object parameters = private_key_algorithm.getParameter();
    if (parameters == null) {
      throw new HIBSInvalidKeyException("No HIBE private key: No parameters specified!");
    }
    HIBSKeyPairParamSpec params = HIBSKeyPairParamSpec.decode(parameters);

    try {
      ASN1 asn1 = new ASN1(privateDelKey);
      if (!asn1.toASN1Object().isA(ASN.SEQUENCE)) {
        throw new HIBSInvalidKeyException("Signature must be ASN.1 SEQUENCE!");
      }

      mKey = decodeDelKey(hibe, asn1);
      params_ = params;

    } catch (CodingException | IOException | DecodingException e) {
      throw new HIBSInvalidKeyException("PrivDelKey not decodable!");
    }
  }

  static DelegatedSecretKey decodeDelKey(Hibe hibe, ASN1 asn1) throws DecodingException, IOException {
    SEQUENCE s = (SEQUENCE) asn1.toASN1Object();
    BigInteger depth = (BigInteger) s.getComponentAt(0).getValue();
    ECPoint a0 = hibe.getPairing().getGroup1().decodePoint(((OCTET_STRING) s.getComponentAt(1)).getWholeValue());
    ECPoint a1 = hibe.getPairing().getGroup2().decodePoint(((OCTET_STRING) s.getComponentAt(2)).getWholeValue());

    SEQUENCE s1 = (SEQUENCE) s.getComponentAt(3);
    List<ECPoint> b = new ArrayList<>();
    for (int i = 0; i < s1.countComponents(); i++) {
      ECPoint e = hibe.getPairing().getGroup1().decodePoint(((OCTET_STRING) s1.getComponentAt(i)).getWholeValue());
      b.add(e);
    }
    return new DelegatedSecretKey(a0, a1, b, depth.intValue());
  }

  void createHIBEPrivateKey() {
    try {
      private_key_algorithm = (AlgorithmID) HIBSProvider.HIBS_ALG.clone();
      private_key_algorithm.setParameter(params_.toASN1Object());

      SEQUENCE s = encodeDelKey(mKey);

      encodedDelPrivKey_ = new ASN1(s).toByteArray();
    } catch (Exception e) {
      throw new iaik.utils.InternalErrorException("Unable to encode key!", e);
    }
    /** super class makes ASN1 {@link public_key_algorithm} using {@link #createPublicKeyInfo()}     */
    createPrivateKeyInfo();
  }

  static SEQUENCE encodeDelKey(DelegatedSecretKey mKey) {
    SEQUENCE s = new SEQUENCE();
    s.addComponent(new INTEGER(mKey.depth));
    s.addComponent(new OCTET_STRING(mKey.a0.encodePoint()));
    s.addComponent(new OCTET_STRING(mKey.a1.encodePoint()));

    SEQUENCE s1 = new SEQUENCE();
    for (ECPoint i : mKey.b) {
      s1.addComponent(new OCTET_STRING(i.encodePoint()));
    }
    s.addComponent(s1);
    return s;
  }

  @Override
  protected byte[] encode() {
    return encodedDelPrivKey_;
  }

  @Override
  public String getAlgorithm() {
    return "HIBE";
  }

  public String toString() {

    StringBuilder builder = new StringBuilder();

    builder.append("Points: ");
    builder.append(mKey.a0.toString());
    builder.append(", ");
    builder.append(mKey.a1.toString());
    builder.append(", ");
    for (ECPoint h : mKey.b) {
      builder.append(h.toString());
    }
    builder.append("\nParameter: ");
    if (params_ != null) {
      builder.append(params_);
    } else {
      builder.append("params not readable");
    }
    builder.append('\n');

    return builder.toString();
  }

  public PublicParams getPP() {
    return params_.getPP();
  }

  public DelegatedSecretKey getDelSecK() {
    return mKey;
  }

  public HIBSKeyPairParamSpec getParams() {
    return params_;
  }
}
