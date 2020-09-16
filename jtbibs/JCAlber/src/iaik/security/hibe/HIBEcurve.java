package iaik.security.hibe;

public enum HIBEcurve {
    BN_P256,
    BN_P461,
    BN_P638,
    ISO_P512;
  }// TODO encode it in keyparams, so that Sign.setParam does not need to specify
