package master.benchmark;

import Entities.SecurityParams;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.hibe.HIBSAlgorithmParameterSpec;
import iaik.security.hibe.HIBSKeyPairParamSpec;
import iaik.security.hibe.HIBSProvider;
import iaik.security.hibe.HIBScurve;
import master.HibeCommon;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.RunnerException;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static iaik.security.hibe.HIBScurve.BN_P461;

@State(Scope.Benchmark)
public class VerifyBench extends ABenchmark{
  private static Logger logger = Logger.getLogger(VerifyBench.class);

  final static byte[] mSignData = "test test test sign".getBytes();
  static Signature mSig;
  static KeyPair mKp;
  static byte[] mSignature;

  @Setup(Level.Trial)
  public void setUp() throws Exception {
    System.out.println("main setup");
    Security.addProvider(ECCelerate.getInstance());
    Security.addProvider(new HIBSProvider());
    HibeCommon.sDebug = false;
    LogManager.shutdown();
  }

  @TearDown(Level.Trial)
  public void tearDown() throws Exception {
  }

  private static void generalSetup(HIBScurve c) throws Exception {
    System.out.println("setup verify");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("HIBE");
    kpg.initialize(HIBSKeyPairParamSpec.create(1, new SecurityParams(c)));
    mKp = kpg.generateKeyPair();
  }

  public static void hibeSetupVerify(HIBScurve c) throws Exception {
    generalSetup(c);

  }

  public void hibeSign(HIBScurve c) throws Exception {
    System.out.println("sign");
    mSig = Signature.getInstance("HIBE");
    mSig.setParameter(new HIBSAlgorithmParameterSpec());
    mSig.initSign(mKp.getPrivate());
    mSig.update(mSignData);
    mSignature = mSig.sign();
  }

  public void hibeVerify(HIBScurve c) throws Exception {
    System.out.println("verify");
    mSig = Signature.getInstance("HIBE");
    mSig.setParameter(new HIBSAlgorithmParameterSpec());
    mSig.initVerify(mKp.getPublic());
    mSig.update(mSignData);
    if (!mSig.verify(mSignature))
      throw new Exception("Did not verified");
  }

  private static void setup_sign(String algo, ECGenParameterSpec ecSpec) throws Exception {
    System.out.println("setup sign");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);
    if (ecSpec != null)
      kpg.initialize(ecSpec);
    mKp = kpg.generateKeyPair();
  }

  private static void setup_verify(String algoKey, String algoSig, ECGenParameterSpec ecSpec) throws Exception {
    System.out.println("setup verify");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(algoKey);
    if (ecSpec != null)
      kpg.initialize(ecSpec);
    mKp = kpg.generateKeyPair();
    mSig = Signature.getInstance(algoSig);
    mSig.initSign(mKp.getPrivate());
    mSig.update(mSignData);
    mSignature = mSig.sign();
  }

  private void sign(String algo) throws Exception {
    System.out.println("sign");
    mSig = Signature.getInstance(algo);
    mSig.initSign(mKp.getPrivate());
    mSig.update(mSignData);
    byte[] s = mSig.sign();
  }

  public void verify(String algo) throws Exception {
    System.out.println("verify");
    mSig = Signature.getInstance(algo);
    mSig.initVerify(mKp.getPublic());
    mSig.update(mSignData);
    if (!mSig.verify(mSignature))
      throw new Exception("Did not verified");
  }

  //------------- BN_P461 ---------------------------------

  @State(Scope.Benchmark)
  public static class State_BN_P461_Verify {
    @Setup(Level.Iteration)
    public void setup() throws Exception {
      hibeSetupVerify(BN_P461);
    }
  }
  @Benchmark
  public void Hibe_BN_P461_verify(State_BN_P461_Verify s) throws Exception {
    hibeVerify(BN_P461);
  }

  public static void main(String[] args) throws RunnerException {
    run(VerifyBench.class);
  }
}
