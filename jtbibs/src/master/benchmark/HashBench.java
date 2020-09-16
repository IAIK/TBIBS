package master.benchmark;

import Entities.PublicParams;
import Entities.SecurityParams;
import HIBE.Hibe;
import iaik.security.hibe.HIBEProvider;
import iaik.security.hibe.HIBEcurve;
import master.HibeCommon;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.RunnerException;

import java.math.BigInteger;
import java.security.Security;
import java.util.Random;

@State(Scope.Benchmark)
public class HashBench extends ABenchmark{
  private static Logger logger = Logger.getLogger(VerifyBench.class);
  private Hibe mHibe;
  private PublicParams mPP;
  private byte[] mRandomBytes;

  @Setup(Level.Trial)
  public void setUp() throws Exception {
    System.out.println("main setup");
    Security.addProvider(new HIBEProvider());
    HibeCommon.sDebug = false;
    LogManager.shutdown();

    mHibe = new Hibe();
    mPP = mHibe.setUp(1, new SecurityParams(HIBEcurve.BN_P461));
  }
  @Setup(Level.Iteration)
  public void setUp2() throws Exception {
    mRandomBytes = new byte[1024];
    new Random().nextBytes(mRandomBytes);
    System.out.println(mRandomBytes.toString());
  }

  @Benchmark
  public void hash() throws Exception {
    BigInteger bi = mPP.hash(mRandomBytes);
  }

  public static void main(String[] args) throws RunnerException {
    run(HashBench.class);
  }
}
