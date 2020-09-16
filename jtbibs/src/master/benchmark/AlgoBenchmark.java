package master.benchmark;

import Entities.SecurityParams;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.hibe.*;
import master.HibeCommon;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.RunnerException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static iaik.security.hibe.HIBEcurve.*;

@State(Scope.Benchmark)
public class AlgoBenchmark extends ABenchmark {
  private static Logger logger = Logger.getLogger(AlgoBenchmark.class);

  final static byte[] mSignData = "test test test sign".getBytes();
  final static byte[][] mSignData2 = {"test".getBytes(), "zwei".getBytes(), "drei".getBytes(), "vier".getBytes(),
      "fünf".getBytes(), "sechs".getBytes(), "sieben".getBytes(), "acht".getBytes(), "neun".getBytes()};
  static Signature mSig;
  static KeyPair mKp;
  static byte[] mSignature;

  @Setup(Level.Trial)
  public void setUp() throws Exception {
    System.out.println("main setup");
    Security.addProvider(ECCelerate.getInstance());
    Security.addProvider(new HIBEProvider());
    HibeCommon.sDebug = false;
    LogManager.shutdown();
  }

  @TearDown(Level.Trial)
  public void tearDown() throws Exception {
  }

  public static void hibeSetupSign(HIBEcurve c) throws Exception {
    System.out.println("setup sign");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("HIBE");
    kpg.initialize(HIBEKeyPairParamSpec.create(1, new SecurityParams(c)));
    mKp = kpg.generateKeyPair();
  }

  public static void hibeSetupVerify(HIBEcurve c) throws Exception {
    System.out.println("setup verify");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("HIBE");
    kpg.initialize(HIBEKeyPairParamSpec.create(9, new SecurityParams(c)));
    mKp = kpg.generateKeyPair();
    for (int i = 0; i < 9; i++) {
      mSig = Signature.getInstance("HIBE");
      mSig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs((i == 0)? new byte[][]{} : Arrays.asList(mSignData2).subList(0,i).toArray(new byte[][]{})));
      mSig.initSign((i == 0)? mKp.getPrivate() : new HIBEDelPrivKey(mSignature));
      mSig.update(mSignData2[i]);
      mSignature = mSig.sign();
    }
  }

  public void hibeSign(HIBEcurve c) throws Exception {
    System.out.println("sign");
    mSig = Signature.getInstance("HIBE");
    mSig.setParameter(new HIBEAlgorithmParameterSpec());
    mSig.initSign(mKp.getPrivate());
    mSig.update(mSignData);
    mSignature = mSig.sign();
  }

  public void hibeVerify(HIBEcurve c) throws Exception {
    System.out.println("verify");
    mSig = Signature.getInstance("HIBE");
    mSig.setParameter(new HIBEAlgorithmParameterSpec().addDelegateIDs(Arrays.asList(mSignData2).subList(0,8).toArray(new byte[][]{})));
    mSig.initVerify(mKp.getPublic());
    mSig.update(mSignData2[8]);
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

  //------------- BN_P256 ---------------------------------
  @State(Scope.Benchmark)
  public static class State_BN_P256_Sign {
    @Setup(Level.Iteration)
    public void setup() throws Exception {
      hibeSetupSign(BN_P256);
    }
  }
  @Benchmark
  public void Hibe_BN_P256_sign(State_BN_P256_Sign s) throws Exception {
    hibeSign(BN_P256);
  }

  @State(Scope.Benchmark)
  public static class State_BN_P256_Verify {
    @Setup(Level.Iteration)
    public void setup() throws Exception {
      hibeSetupVerify(BN_P256);
    }
  }
  @Benchmark
  public void Hibe_BN_P256_verify(State_BN_P256_Verify s) throws Exception {
    hibeVerify(BN_P256);
  }
//  //------------- BN_P461 ---------------------------------
//  @State(Scope.Benchmark)
//  public static class State_BN_P461_Sign {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      hibeSetupSign(BN_P461);
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P461_sign(State_BN_P461_Sign s) throws Exception {
//    hibeSign(BN_P461);
//  }
//
//  @State(Scope.Benchmark)
//  public static class State_BN_P461_Verify {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      hibeSetupVerify(BN_P461);
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P461_verify(State_BN_P461_Verify s) throws Exception {
//    hibeVerify(BN_P461);
//  }
//
//  //------------- BN_P638 ---------------------------------
//  @State(Scope.Benchmark)
//  public static class State_BN_P638_Sign {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      hibeSetupSign(BN_P638);
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P638_sign(State_BN_P638_Sign s) throws Exception {
//    hibeSign(BN_P638);
//  }
//
//  @State(Scope.Benchmark)
//  public static class State_BN_P638_Verify {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      hibeSetupVerify(BN_P638);
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P638_verify(State_BN_P638_Verify s) throws Exception {
//    hibeVerify(BN_P638);
//  }
//
//  //----------------- ISO_P512 ----------------------------
//  @State(Scope.Benchmark)
//  public static class State_ISO_P512_Sign {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      hibeSetupSign(ISO_P512);
//    }
//  }
//  @Benchmark
//  public void Hibe_ISO_P512_sign(State_ISO_P512_Sign s) throws Exception {
//    hibeSign(ISO_P512);
//  }
//
//  @State(Scope.Benchmark)
//  public static class State_ISO_P512_Verify {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      hibeSetupVerify(ISO_P512);
//    }
//  }
//  @Benchmark
//  public void Hibe_ISO_P512_verify(State_ISO_P512_Verify s) throws Exception {
//    hibeVerify(ISO_P512);
//  }

//  //---------------- Ed25519 ------------------------------
//  @State(Scope.Benchmark)
//  public static class State_Ed25519_Sign {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      setup_sign("Ed25519", null);
//    }
//  }
//  @Benchmark
//  public void Ed25519_sign(State_Ed25519_Sign s) throws Exception {
//    sign("Ed25519");
//  }
//
//  @State(Scope.Benchmark)
//  public static class State_Ed25519_Verify {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      setup_verify("Ed25519", "Ed25519",null);
//    }
//  }
//  @Benchmark
//  public void Ed25519_verify(State_Ed25519_Verify s) throws Exception {
//    verify("Ed25519");
//  }
//
//
////  //------------- ECDSA -----------------------------------
//@State(Scope.Benchmark)
//public static class State_ECDSA_Sign {
//  @Setup(Level.Iteration)
//  public void setup() throws Exception {
//    ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
//    setup_sign("EC", ecSpec);
//  }
//}
//  @Benchmark
//  public void ECDSA_sign(State_ECDSA_Sign s) throws Exception {
//    sign("SHA256withECDSA");
//  }
//
//  @State(Scope.Benchmark)
//  public static class State_ECDSA_Verify {
//    @Setup(Level.Iteration)
//    public void setup() throws Exception {
//      ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
//      setup_verify("EC", "SHA256withECDSA", ecSpec);
//    }
//  }
//  @Benchmark
//  public void ECDSA_verify(State_ECDSA_Verify s) throws Exception {
//    verify("SHA256withECDSA");
//  }


  public static void main(String[] args) throws RunnerException {
    run(AlgoBenchmark.class);
  }
}
