package iaik.security.hibe;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactory for converting HIBE keys (opaque representation) to KeySpecs (transparent representation)
 * and vice versa.
 * <ul>
 * <li>HIBEPublicKey  <--> X509EncodedKeySpec
 * <li>HIBEPrivateKey  <--> PKCS8EncodedKeySpec
 * </ul>
 * To convert, for instance, DER encoded PKCS#8 private key material 
 * into a HIBEPrivateKey use:
 * <pre>
 * PKCS8EncodedKeySpec pkcs8KeySpec = ...;
 * KeyFactory kf = KeyFactory.getInstance("HIBE");
 * HIBEPrivateKey privKey = (HIBEPrivateKey)kf.generatePrivate(pkcs8KeySpec);
 * </pre></blockquote><p>
 */
public final class HIBEKeyFactory extends KeyFactorySpi {

	/**
	 * Default constructor for creating a HIBEKeyFactory.
	 * Applications shall use
	 * <blockquote><pre>
	 * KeyFactory.getInstance("HIBE");
	 * </pre></blockquote> for instantiating a HIBEKeyFactory.
	 *
	 */
	public HIBEKeyFactory() {
	}

	/**
	 * Converts the given key specification to a PrivateKey.
	 * <p>
	 * The given key material  must be a PKCS8EncodedKeySpec.
	 *
	 * @param keySpec the key specification as PKCS8EncodedKeySpec
	 * 
	 * @return the resulting PrivateKey
	 *
	 * @exception InvalidKeySpecException if the given key material is not
	 *                                    a PKCS8EncodedKeySpec
	 */
  @Override
	protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
	  throws InvalidKeySpecException {
	  PrivateKey pk = null;
		
		if (keySpec instanceof PKCS8EncodedKeySpec) {
			try {
			  pk = new HIBEPrivateKey(((PKCS8EncodedKeySpec)keySpec).getEncoded());
			} catch (InvalidKeyException e) {
		    throw new InvalidKeySpecException("Invalid KeySpec: " + e.getMessage(), e);
		  }
	  } else {
		  throw new InvalidKeySpecException("Only PKCS8EncodedKeySpecs allowed.");
		}
		return pk;
	}

	/**
	 * Converts the given key specification to a PublicKey.
	 * <p>
	 * The given key material must be a X509EncodedKeySpec.
	 *
	 * @param keySpec the key specification as X509EncodedKeySpec
	 * 
	 * @return the resulting PublicKey
	 *
	 * @exception InvalidKeySpecException if the given key material is not
	 *                                    a X509EncodedKeySpec
	 */
  @Override
	protected PublicKey engineGeneratePublic(KeySpec keySpec)
	    throws InvalidKeySpecException
	{
	  PublicKey pk = null;
	  if (keySpec instanceof X509EncodedKeySpec) {
		  try {
			  pk = new HIBEPublicKey(((X509EncodedKeySpec) keySpec).getEncoded());
  		} catch (InvalidKeyException e) {
	  		throw new InvalidKeySpecException("Invalid KeySpec: " + e.getMessage(), e);
		  }
	  } else {
	    throw new InvalidKeySpecException("Only X509EncodedKeySpec allowed.");
	  }
	  return pk;
	            
	}

	/**
	 * Converts the given key into the requested key specification (key material).
	 * <p>
	 * The given key may either be a HIBEPublicKey or a HIBEPrivateKey. If the key is a
	 * HIBEPublicKey, this method only can create a X509EncodedKeySpec from it. If the 
	 * given key is a HIBEPrivateKey a PKCS8EncodedKeySpec may be returned. Each attempt 
	 * to get key material of a type not matching to a given HIBE key will raise an exception.
	 *
	 * @param key the key to be converted, which either may be a HIBEPublicKey or a HIBEPrivateKey.
	 * @param classSpec the key specification type into which the key shall be converted, which may be
	 *                a X509EncodedKeySpec if the given key is a HIBEPublicKey, or
	 *                a PKCS8EncodedKeySpec if the given key is a HIBEPrivateKey
	 * @return the key specification (key material) derived from the given key
	 *
	 * @exception InvalidKeySpecException if the given key cannot be converted into the
	 *                                    requested key specification object by this key factory
	 */
	@SuppressWarnings("unchecked")
  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, final Class<T> classSpec)
    throws InvalidKeySpecException {
	
	  KeySpec keySpec = null;
		if (key instanceof HIBEPublicKey) {

			if (X509EncodedKeySpec.class.isAssignableFrom(classSpec)) {
				keySpec = new X509EncodedKeySpec(key.getEncoded());
			} else {
			  throw new InvalidKeySpecException("Can't convert key to KeySpec.");
			}
		} else if (key instanceof HIBEPrivateKey) {

			
			if (PKCS8EncodedKeySpec.class.isAssignableFrom(classSpec)) {
				keySpec = new PKCS8EncodedKeySpec(key.getEncoded());
			} else { 
			  throw new InvalidKeySpecException("Can't convert key to KeySpec.");
			}
		} else {
		  throw new InvalidKeySpecException("Can only convert HIBE keys.");
		}
		return (T) keySpec;
	}

	/**
	 * Translates the given key object of some unknown or untrusted provider into a
	 * key object supported by this HIBE key factory.
	 * This method only can translate keys of type <code>HIBEPublicKey</code> or
	 * <code>HIBEPrivateKey</code>.
	 *
	 * @param key the key of some unknown or untrusted provider
	 * @return the translated key
	 *
	 * @exception InvalidKeyException
	 *            if the given key cannot be translated by this key factory
	 */
	protected Key engineTranslateKey(Key key)
	    throws InvalidKeyException
	{
		if (key instanceof HIBEPublicKey) {
			return (HIBEPublicKey)key;
		} else if (key instanceof HIBEPrivateKey) {
			return (HIBEPrivateKey)key;
		} else throw new HIBEInvalidKeyException(
		    "Only keys of type HIBEPublicKey and HIBEPrivateKey can be translated.");
	}
}
