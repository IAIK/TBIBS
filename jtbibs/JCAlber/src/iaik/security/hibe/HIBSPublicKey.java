package iaik.security.hibe;

import java.security.InvalidKeyException;

import Entities.PublicParams;
import iaik.asn1.*;
import iaik.asn1.structures.AlgorithmID;
import iaik.security.ec.math.curve.ECPoint;
import iaik.x509.PublicKeyInfo;

/**
 * HIBE public key.
 */
public class HIBSPublicKey extends PublicKeyInfo
{

	private ECPoint p_;
	private transient byte[] encodedPublicKey_;
	
	/**
   * Domain parameters of the elliptic curve
   */
  private transient HIBSKeyPairParamSpec params_;

	
	/**
	 * Constructor.
	 */
	public HIBSPublicKey(final HIBSKeyPairParamSpec params, final ECPoint pubKey) {
		if ((params == null) || (pubKey == null)) {
			throw new NullPointerException("At least one of params, w is null!");
		}
		else if (!params.getG2().equals(pubKey.getCurve())) { // TODO check even possible with ?g_head^alpha?
			throw new IllegalArgumentException("w is not a point on the curve specified by params!");
		}

    params_ = params;
		p_  = pubKey;
	  createHIBEPublicKey();
	}

	
	/**
	 * Creates a new HIBEPublicKey from the given DER encoded byte array.
	 * @param endcoded
	 *          the byte array holding the DER encoded public key info
	 * @exception InvalidKeyException
	 *              if something is wrong with the key encoding
	 */
	public HIBSPublicKey(byte[] endcoded)
	    throws InvalidKeyException
	{
		super(endcoded);
	}

	/**
	 * Creates a new HIBEPublicKey from the given ASN.1 object. The supplied
	 * ASN1Object represents a X.509 PublicKeyInfo holding the HIBE public key.
	 * 
	 * @param obj
	 *          the public key ASN.1 structure
	 * 
	 * @exception InvalidKeyException
	 *              if something is wrong with the key encoding
	 */
	public HIBSPublicKey(ASN1Object obj)
	    throws InvalidKeyException
	{
		super(obj);
	}

	
	/**
	 * Decodes a HIBEPublicKey, encoded in DER format.
	 * 
	 * @param publicKey
	 *          the public key as DER encoded HIBE key
	 * 
	 * @exception InvalidKeyException
	 *              if something is wrong with the encoding of the key
	 */
	@Override
	protected void decode(byte[] publicKey)
	    throws InvalidKeyException
	{

		try {

		  encodedPublicKey_ = publicKey;
			final ASN1Object parameters = public_key_algorithm.getParameter();
			if (parameters == null) {
				throw new HIBSInvalidKeyException("No HIBE public key: No parameters specified!");
			}

			HIBSKeyPairParamSpec params = HIBSKeyPairParamSpec.decode(parameters);

			final ECPoint pTmp = params.getG2().decodePoint(encodedPublicKey_);

			params_ = params;
			p_ = pTmp;

		} catch (Exception ex) {
			throw new HIBSInvalidKeyException("Error parsing key: " + ex.getMessage(), ex);
		}
	}


	/**
	 * Creates a HIBEPublicKey object
	 */
	void createHIBEPublicKey() {

  	try {
  	  public_key_algorithm = (AlgorithmID) HIBSProvider.HIBS_ALG.clone();
      public_key_algorithm.setParameter(params_.toASN1Object());
      encodedPublicKey_ = params_.getG2().encodePoint(p_);
		} catch (final Exception e) {
			throw new RuntimeException("Unable to encode key!", e);
		}

		/** super class makes ASN1 {@link public_key_algorithm} using {@link #createPublicKeyInfo()} 		 */
		createPublicKeyInfo();
		
	}

	/**
	 * Returns the raw HIBE public key (not wrapped in a X.509
	 * PublicKeyInfo) as DER encoded ASN.1 object.
	 * 
	 * @return a byte array holding the HIBE public key as a DER encoded ASN.1
	 *         data structure 
	 */
	public byte[] encode() {
		return encodedPublicKey_;
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
	 * Returns a string that represents the contents of this HIBE public key.
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

	/**
	 * Compares this HIBEPublicKey object with the supplied object.
	 * 
	 * @param obj
	 *          the object to be compared
	 * 
	 * @return <code>true</code> if the two objects are HIBEPublicKey objects with
	 *         same modulus and exponent, <code>false</code> otherwise
	 */
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof HIBSPublicKey)) {
			return false;
		}
		HIBSPublicKey other = (HIBSPublicKey) obj;

		return super.equals(other);
	}

	public ECPoint getP() {
		return p_;
	}

	public PublicParams getPP() {
		return params_.getPP();
	}
}
