package master.iaikProviderImpl;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import Entities.SecurityParams;
import iaik.security.hibe.HIBEAlgorithmParameterSpec;
import iaik.security.hibe.HIBEKeyPairParamSpec;
import iaik.security.hibe.HIBEPublicKey;
import iaik.security.hibe.HIBEUtils;
import iaik.security.ssl.*;

public class IaikHibeProvider extends ECCelerateProvider {

  final static String ALG_SIGNATURE_HIBE = "HIBE";
  @Override
  public SupportedEllipticCurves.NamedCurve getCurve(PublicKey publicKey) {
    if (publicKey instanceof HIBEPublicKey){
      return SupportedEllipticCurves.HIBE;
    }
    return super.getCurve(publicKey);
  }

  @Override
  public boolean isNamedCurveSupported(SupportedEllipticCurves.NamedCurve namedCurve) {
    if (namedCurve.equals(SupportedEllipticCurves.HIBE))
      return true;
    return super.isNamedCurveSupported(namedCurve);
  }

  @Override
  public KeyPair generateECKeyPair(SupportedEllipticCurves supportedEllipticCurves, SupportedPointFormats supportedPointFormats) throws Exception {
    if (Arrays.asList(supportedEllipticCurves.getEllipticCurveList()).contains(SupportedEllipticCurves.HIBE)) {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("HIBE");
      kpg.initialize(HIBEKeyPairParamSpec.create(3, new SecurityParams()));
      return kpg.generateKeyPair();
    }
    return super.generateECKeyPair(supportedEllipticCurves, supportedPointFormats);
  }

  @Override
  public byte[] encodeECPublicKey(PublicKey publicKey, SupportedPointFormats supportedPointFormats) throws Exception {
    if (publicKey instanceof HIBEPublicKey) {
      return publicKey.getEncoded();
    }
    return super.encodeECPublicKey(publicKey, supportedPointFormats);
  }

  @Override
  public PublicKey decodeECPublicKey(byte[] bytes, SupportedEllipticCurves.NamedCurve curve, SupportedPointFormats formats, SupportedEllipticCurves supportedCurves) throws Exception {
    if (curve.equals(SupportedEllipticCurves.HIBE)) {
      return new HIBEPublicKey(bytes);
    }
    return super.decodeECPublicKey(bytes, curve, formats, supportedCurves);
  }

  @Override
  public SupportedPointFormats.ECPointFormat getECPointFormat(PublicKey publicKey) {
    if (publicKey instanceof HIBEPublicKey) {
      return SupportedPointFormats.PF_UNCOMPRESSED;
    }
    return super.getECPointFormat(publicKey);
  }

  /**
   * This method returns the desired Signature object.
   *
   * @param algorithm the name of the signature algorithm
   * @param mode the initialization mode, either
   *        {@link #SIGNATURE_NONE <CODE>SIGNATURE_NONE</CODE>},
   *        {@link #SIGNATURE_SIGN <CODE>SIGNATURE_SIGN</CODE>} or
   *        {@link #SIGNATURE_VERIFY <CODE>SIGNATURE_VERIFY</CODE>} indicating
   *        whether to not initialize the signature engine at all, or
   *        to initialize it for signing or verifying with the given
   *        key
   * @param key the key to be used to initialize the Signature engine
   * @param certChain; if not <code>null</code> containing the
   *        key to be used for verifying the signature
   * @param transport containing all TLS extensions
   *
   * @return the (maybe initialized) Signature engine
   */
  protected Signature getSignature(String algorithm,
      int mode, Key key, X509Certificate[] certChain,
      SSLTransport transport, SecureRandom random) throws Exception {
    Signature sig = null;
    if (ALG_SIGNATURE_HIBE.equals(algorithm)) {
      sig = Signature.getInstance("HIBE");
      ServerName[] serverNames = null;
      ExtensionList extensions = transport.getActiveExtensions();
      if (extensions != null) {
        serverNames = ((ServerNameList)extensions.getExtension(ServerNameList.TYPE)).getServerNames();
      }



      if (serverNames != null && serverNames.length != 0) {
        byte[] domain = serverNames[0].getEncodedName(); //currently the domain, but could be a subdomain for fine-grained privilege delegation
        byte[] epoch = HIBEUtils.getEpoch(HIBEUtils.EpochGranularity.Day);
        sig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(domain, epoch));
      } else throw new Exception("No SNI set");

      if (key instanceof PrivateKey) {
        sig.initSign((PrivateKey)key);
      } else {
        sig.initVerify((PublicKey)key);
      }
    } else {
      sig = super.getSignature(algorithm, mode, key, certChain, transport, random);
    }
    return sig;
  }
}
