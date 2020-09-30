package iaik.security.hibe;

import Entities.DelegatedSecretKey;
import Entities.PublicParams;
import HIBE.Hibe;
import iaik.security.ec.math.curve.ECPoint;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class HIBSWithSHA256Signature extends SignatureSpi {

  private static Logger logger = Logger.getLogger(HIBSWithSHA256Signature.class);

  enum SignatureAction {
    SIGNING,
    VERIFYING;
  }

  private SignatureAction mDoing;

  private PrivateKey mPrivateKey;
  private ByteArrayOutputStream mData = new ByteArrayOutputStream();
  private PublicKey mPublicKey;

  private HIBSAlgorithmParameterSpec mSpec = new HIBSAlgorithmParameterSpec();

  //TODO finish error handling

  //TODO are there Rules in which order this method has to be used respectively to the other
  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    if (!(params instanceof HIBSAlgorithmParameterSpec))
      throw new HIBSInvalidAlgorithmParameterException("Parameters not from type HIBEAlgorithmParameterSpec");

    mSpec = (HIBSAlgorithmParameterSpec) params;
    if (!mSpec.complete()) {
      mSpec = new HIBSAlgorithmParameterSpec();
      throw new HIBSInvalidAlgorithmParameterException("HIBEAlgorithmParameterSpec are incomplete");
    }
  }

  @Deprecated
  @Override
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Deprecated
  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }


  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (privateKey == null)
      throw new HIBSInvalidKeyException("Private key can not be null");
    mPrivateKey = privateKey;
    mData.reset();
    mDoing = SignatureAction.SIGNING;
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    if (mPrivateKey == null && mPublicKey == null)
      throw new HIBSSignaturException("Signature must be initialized first");
    mData.write(b);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) throws SignatureException {
    if (mPrivateKey == null && mPublicKey == null)
      throw new HIBSSignaturException("Signature must be initialized first");
    if (input == null)
      throw new HIBSSignaturException("No input buffer given");
    if (input.length - offset < len)
      throw new HIBSSignaturException("Input buffer too short");
    mData.write(input, offset, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (!mDoing.equals(SignatureAction.SIGNING))
      throw new HIBSSignaturException("Sign can not be called without initSign first");
    if (mPrivateKey == null)
      throw new HIBSSignaturException("Signature must be initialized first");
    else if (mData == null)
      throw new HIBSSignaturException("Signature must be fed data first");

    Hibe hibe = new Hibe();
    DelegatedSecretKey ds;
    if (mPrivateKey instanceof HIBSPrivateKey) {
      PublicParams pp = ((HIBSPrivateKey) mPrivateKey).getPP();
      if (mSpec.mIDs.size() > 0)
        throw new HIBSSignaturException("Number of IDs not matching delegation depth");

      ECPoint secK = ((HIBSPrivateKey) mPrivateKey).getP();
      ds = hibe.delegation(pp, secK, mData.toByteArray());
      return encode(ds, ((HIBSPrivateKey) mPrivateKey).getParams());
    } else if (mPrivateKey instanceof HIBSDelPrivKey) {
      DelegatedSecretKey delSecK = ((HIBSDelPrivKey) mPrivateKey).getDelSecK();
      if (mSpec.mIDs.size() != delSecK.depth)
        throw new HIBSSignaturException("Number of IDs not matching delegation depth");

      PublicParams pp = ((HIBSDelPrivKey) mPrivateKey).getPP();
      pp.ID.addAll(mSpec.mIDs);
      ds = hibe.delegation(pp, delSecK, mData.toByteArray());
      return encode(ds, ((HIBSDelPrivKey) mPrivateKey).getParams());
    } else
      throw new HIBSSignaturException("Trying to sign with unsupported private key!");
  }

  @Deprecated
  public static HIBSDelPrivKey delegate(HIBSKeyPairParamSpec params, PrivateKey aPrivate, byte[] delData) {
    Hibe hibe = new Hibe();
    PublicParams pp = ((HIBSPrivateKey) aPrivate).getPP(); //TODO distinguish between
    ECPoint secK = ((HIBSPrivateKey) aPrivate).getP();
    DelegatedSecretKey ds = hibe.delegation(pp, secK, delData);
    return new HIBSDelPrivKey(params, ds);
  }

  private byte[] encode(DelegatedSecretKey ds, HIBSKeyPairParamSpec params) throws SignatureException {
    HIBSDelPrivKey secK = new HIBSDelPrivKey(params, ds);
    return secK.getEncoded();
  }

  private DelegatedSecretKey decode(byte[] sigBytes) throws SignatureException {
    try {
      HIBSDelPrivKey delPrivKey = new HIBSDelPrivKey(sigBytes);
      return delPrivKey.getDelSecK();
    } catch (InvalidKeyException e) {
      throw new HIBSSignaturException(e.getMessage());
    }
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (publicKey == null)
      throw new HIBSInvalidKeyException("Public key can not be null");

    mPublicKey = publicKey;
    mData.reset();
    mDoing = SignatureAction.VERIFYING;
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (!mDoing.equals(SignatureAction.VERIFYING))
      throw new HIBSSignaturException("Verify can not be called without initVerify first");
    if (mPublicKey == null)
      throw new HIBSSignaturException("Verify must be initialized first");
    if (sigBytes == null)
      throw new HIBSSignaturException("Can not verify signature of null"); //TODO check if necessary
    DelegatedSecretKey dgs = decode(sigBytes);
    if (mSpec.mIDs.size() != dgs.depth - 1)
      throw new HIBSSignaturException("Not correct IDs feeded");

    Hibe hibe = new Hibe();
    ECPoint pk = ((HIBSPublicKey) mPublicKey).getP();
    PublicParams pp = ((HIBSPublicKey) mPublicKey).getPP();
    for (byte[] id : mSpec.mIDs) {
      pp.addID(id);
    }
    pp.addID(mData.toByteArray());

    if (pp.ID.size() != dgs.depth) {
      throw new HIBSSignaturException("The delegation depth is not equal the amount of IDs");
    }

    return hibe.ntDeterVerify(pp, pk, dgs);

//    return hibe.ntDeterVerify(pp, pk, dgs);

//    ExtensionFieldElement gt = hibe.getPairing().getTargetGroup().getUniformlyRandomNonZeroElement();
//    ChipherText ct = hibe.encrypt(pk, gt, pp);
//    ExtensionFieldElement m = hibe.decrypt(pp, dgs, ct);
//    return m.equals(gt);
  }
}
