package iaik.security.hibe;

import Entities.MasterKeyPair;
import Entities.PublicParams;
import HIBE.Hibe;
import org.apache.log4j.Logger;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class HIBSKeyPairGenerator extends KeyPairGeneratorSpi {
  private static Logger logger = Logger.getLogger(HIBSKeyPairGenerator.class);
  private Hibe mHibe;
  private PublicParams mPP;


  public HIBSKeyPairGenerator() {
    logger.info("KeyPairGenerator Hibe selected");
    mHibe = new Hibe();
  }

  @Deprecated
  @Override
  public void initialize(int keysize, SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
    if (params == null)
      throw new HIBSInvalidAlgorithmParameterException("AlgorithmParameterSpec parameters can not be null");
    if (!(params instanceof HIBSKeyPairParamSpec))
      throw new HIBSInvalidAlgorithmParameterException("Parameters not of type HIBEsetupParameterSpec");

    mPP = ((HIBSKeyPairParamSpec) params).getPP();
  }

  @Override
  public KeyPair generateKeyPair() {
    if (mPP == null) {
      throw new RuntimeException("Key Pair Generator needs to be initialized first");
      // TODO own exception
    }
    logger.info("KeyPairGenerator keypair generated");

    MasterKeyPair keyPair = mHibe.keyGen(mPP);
    HIBSKeyPairParamSpec pp_spec = HIBSKeyPairParamSpec.generateToSpec(mPP);
    return new KeyPair(new HIBSPublicKey(pp_spec, keyPair.pubKey),
        new HIBSPrivateKey(pp_spec, keyPair.secKey));
  }

}
