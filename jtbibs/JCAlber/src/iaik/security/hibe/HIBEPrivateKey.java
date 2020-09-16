package iaik.security.hibe;

import java.security.InvalidKeyException;

import Entities.PublicParams;
import iaik.asn1.*;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs8.PrivateKeyInfo;
import iaik.security.ec.math.curve.ECPoint;

/**
 * HIBE private key.
 */
public class HIBEPrivateKey extends PrivateKeyInfo {

  private ECPoint p_;
  private transient byte[] encodedPrivateKey_;

  public static final INTEGER EC_PRIVATE_KEY_VERSION = new INTEGER(333);

  /**
   * Domain parameters of the elliptic curve
   */
  private transient HIBEKeyPairParamSpec params_;

  /**
   * Constructor.
   */
  public HIBEPrivateKey(HIBEKeyPairParamSpec params, ECPoint secKey) {
    if ((params == null) || (secKey == null)) {
      throw new NullPointerException("At least one of params, w is null!");
    } else if (!params.getG1().equals(secKey.getCurve())) {
      throw new IllegalArgumentException("w is not a point on the curve specified by params!");
    }
    params_ = params;
    p_ = secKey;
    createHIBEPrivateKey();
  }


  /**
   * Creates a new HIBEPrivateKey from a DER encoded ASN.1 data structure
   * representing the PKCS#8 encoded private key.
   *
   * @param endcoded the byte array holding the DER encoded private key info
   * @throws InvalidKeyException if something is wrong with the key encoding
   */
  public HIBEPrivateKey(byte[] endcoded)
      throws InvalidKeyException {
    super(endcoded);
  }

  /**
   * Creates a new private key from an ASN1Object representing a PKCS#8
   * PrivateKeyInfo holding the HIBE private key.
   *
   * @param obj the private key as ASN1Object
   * @throws InvalidKeyException if something is wrong with the key encoding
   */
  public HIBEPrivateKey(ASN1Object obj)
      throws InvalidKeyException {
    super(obj);
  }


  /**
   * Decodes a DER encoded HIBEPrivateKey.
   *
   * @param encodedPrivateKey the HIBE private key as DER encoded byte array
   * @throws InvalidKeyException if the given key is not a HIBE private key
   */
  protected void decode(byte[] encodedPrivateKey)
      throws InvalidKeyException {

    try {
      encodedPrivateKey_ = encodedPrivateKey;

      final ASN1Object parameters = private_key_algorithm.getParameter();
      if (parameters == null) {
        throw new HIBEInvalidKeyException("No HIBE private key: No parameters specified!");
      }
      HIBEKeyPairParamSpec params = HIBEKeyPairParamSpec.decode(parameters);

			final ECPoint pTmp = params.getG1().decodePoint(encodedPrivateKey_);

			params_ = params;
			p_ = pTmp;

    } catch (Exception e) {
      throw new HIBEInvalidKeyException("Error parsing key: " + e.getMessage(), e);
    }
  }


  /**
   * Creates a HIBEPrivateKey.
   * * <pre>
   *    * ECPrivateKey ::= SEQUENCE {
   *    *   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
   *    *   privateKey OCTET STRING,
   *    *   parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
   *    *   publicKey [1] BIT STRING OPTIONAL
   *    * }
   *    * </pre>
   */
  void createHIBEPrivateKey() {

    try {
      private_key_algorithm = (AlgorithmID) HIBEProvider.HIBE_ALG.clone();
      private_key_algorithm.setParameter(params_.toASN1Object());
      encodedPrivateKey_ = params_.getG1().encodePoint(p_);
    } catch (Exception e) {
      throw new iaik.utils.InternalErrorException("Unable to encode key!", e);
    }
		/** super class makes ASN1 {@link public_key_algorithm} using {@link #createPublicKeyInfo()} 		 */
    createPrivateKeyInfo();
  }

  /**
   * Returns the raw (PKCS#1) HIBE private key (not wrapped in a PKCS#8
   * PrivateKeyInfo) as DER encoded byte array.
   *
   * @return the HIBE private key as a DER encoded ASN.1 data structure
   */
  public byte[] encode() {
    return encodedPrivateKey_;
  }


  /**
   * Returns the name of the appertaining algorithm.
   *
   * @return the string "HIBE"
   */
  public String getAlgorithm() {
    return "HIBE";
  }

  /**
   * Returns a string that represents the contents of this private key.
   *
   * @return the string representation
   */
  public String toString() {

		StringBuilder builder = new StringBuilder();

		builder.append("Point: ");
		builder.append(p_.toString());
		builder.append("\nParameter: ");

		if (params_ != null) {
			builder.append(params_);
		} else {
			builder.append("params not readable"); //ToDO
		}
		builder.append('\n');

		return builder.toString();
	}

  public PublicParams getPP() {
    return params_.getPP();
  }

  public ECPoint getP() {
    return p_;
  }

  public HIBEKeyPairParamSpec getParams() {
    return params_;
  }
}
