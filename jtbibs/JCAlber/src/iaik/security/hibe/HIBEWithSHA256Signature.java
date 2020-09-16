package iaik.security.hibe;

import Entities.DelegatedSecretKey;
import Entities.PublicParams;
import HIBE.Hibe;
import iaik.security.ec.math.curve.ECPoint;
import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class HIBEWithSHA256Signature extends SignatureSpi {

  private static Logger logger = Logger.getLogger(HIBEWithSHA256Signature.class);

  enum SignatureAction {
    SIGNING,
    VERIFYING;

  }

  private SignatureAction mDoing;

  private PrivateKey mPrivateKey;
  private ByteArrayOutputStream mData = new ByteArrayOutputStream();
  private PublicKey mPublicKey;

  private HIBEAlgorithmParameterSpec mSpec = new HIBEAlgorithmParameterSpec();

  //TODO finish error handling

  //TODO are there Rules in which order this method has to be used respectively to the other
  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    if (!(params instanceof HIBEAlgorithmParameterSpec))
      throw new HIBEInvalidAlgorithmParameterException("Parameters not from type HIBEAlgorithmParameterSpec");

    mSpec = (HIBEAlgorithmParameterSpec) params;
    if (!mSpec.complete()) {
      mSpec = new HIBEAlgorithmParameterSpec();
      throw new HIBEInvalidAlgorithmParameterException("HIBEAlgorithmParameterSpec are incomplete");
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
      throw new HIBEInvalidKeyException("Private key can not be null");
    mPrivateKey = privateKey;
    mData.reset();
    mDoing = SignatureAction.SIGNING;
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    if (mPrivateKey == null && mPublicKey == null)
      throw new HIBESignaturException("Signature must be initialized first");
    mData.write(b);
  }

  @Override
  protected void engineUpdate(byte[] input, int offset, int len) throws SignatureException {
    if (mPrivateKey == null && mPublicKey == null)
      throw new HIBESignaturException("Signature must be initialized first");
    if (input == null)
      throw new HIBESignaturException("No input buffer given");
    if (input.length - offset < len)
      throw new HIBESignaturException("Input buffer too short");
    mData.write(input, offset, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (!mDoing.equals(SignatureAction.SIGNING))
      throw new HIBESignaturException("Sign can not be called without initSign first");
    if (mPrivateKey == null)
      throw new HIBESignaturException("Signature must be initialized first");
    else if (mData == null)
      throw new HIBESignaturException("Signature must be fed data first");

    Hibe hibe = new Hibe();
    DelegatedSecretKey ds;
    if (mPrivateKey instanceof HIBEPrivateKey) {
      PublicParams pp = ((HIBEPrivateKey) mPrivateKey).getPP();
      if (mSpec.mIDs.size() > 0)
        throw new HIBESignaturException("Number of IDs not matching delegation depth");

      ECPoint secK = ((HIBEPrivateKey) mPrivateKey).getP();
      ds = hibe.delegation(pp, secK, mData.toByteArray());
      return encode(ds, ((HIBEPrivateKey) mPrivateKey).getParams());
    } else if (mPrivateKey instanceof HIBEDelPrivKey) {
      DelegatedSecretKey delSecK = ((HIBEDelPrivKey) mPrivateKey).getDelSecK();
      if (mSpec.mIDs.size() != delSecK.depth)
        throw new HIBESignaturException("Number of IDs not matching delegation depth");

      PublicParams pp = ((HIBEDelPrivKey) mPrivateKey).getPP();
      pp.ID.addAll(mSpec.mIDs);
      ds = hibe.delegation(pp, delSecK, mData.toByteArray());
      return encode(ds, ((HIBEDelPrivKey) mPrivateKey).getParams());
    } else
      throw new HIBESignaturException("Trying to sign with unsupported private key!");
  }

  @Deprecated
  public static HIBEDelPrivKey delegate(HIBEKeyPairParamSpec params, PrivateKey aPrivate, byte[] delData) {
    Hibe hibe = new Hibe();
    PublicParams pp = ((HIBEPrivateKey) aPrivate).getPP(); //TODO distinguish between
    ECPoint secK = ((HIBEPrivateKey) aPrivate).getP();
    DelegatedSecretKey ds = hibe.delegation(pp, secK, delData);
    return new HIBEDelPrivKey(params, ds);
  }

  private byte[] encode(DelegatedSecretKey ds, HIBEKeyPairParamSpec params) throws SignatureException {
    HIBEDelPrivKey secK = new HIBEDelPrivKey(params, ds);
    return secK.getEncoded();
  }

  private DelegatedSecretKey decode(byte[] sigBytes) throws SignatureException {
    try {
      HIBEDelPrivKey delPrivKey = new HIBEDelPrivKey(sigBytes);
      return delPrivKey.getDelSecK();
    } catch (InvalidKeyException e) {
      throw new HIBESignaturException(e.getMessage());
    }
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (publicKey == null)
      throw new HIBEInvalidKeyException("Public key can not be null");

    mPublicKey = publicKey;
    mData.reset();
    mDoing = SignatureAction.VERIFYING;
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (!mDoing.equals(SignatureAction.VERIFYING))
      throw new HIBESignaturException("Verify can not be called without initVerify first");
    if (mPublicKey == null)
      throw new HIBESignaturException("Verify must be initialized first");
    if (sigBytes == null)
      throw new HIBESignaturException("Can not verify signature of null"); //TODO check if necessary
    DelegatedSecretKey dgs = decode(sigBytes);
    if (mSpec.mIDs.size() != dgs.depth - 1)
      throw new HIBESignaturException("Not correct IDs feeded");

    Hibe hibe = new Hibe();
    ECPoint pk = ((HIBEPublicKey) mPublicKey).getP();
    PublicParams pp = ((HIBEPublicKey) mPublicKey).getPP();
    for (byte[] id : mSpec.mIDs) {
      pp.addID(id);
    }
    pp.addID(mData.toByteArray());

    if (pp.ID.size() != dgs.depth) {
      throw new HIBESignaturException("The delegation depth is not equal the amount of IDs");
    }

    return hibe.ntDeterVerify(pp, pk, dgs);

//    return hibe.ntDeterVerify(pp, pk, dgs);

//    ExtensionFieldElement gt = hibe.getPairing().getTargetGroup().getUniformlyRandomNonZeroElement();
//    ChipherText ct = hibe.encrypt(pk, gt, pp);
//    ExtensionFieldElement m = hibe.decrypt(pp, dgs, ct);
//    return m.equals(gt);
  }
}
