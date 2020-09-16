package master.benchmark;

import HIBE.Hibe;
import iaik.security.ec.provider.ECCelerate;
import master.*;
import master.benchmark.tls13.TLS13Client;
import master.benchmark.tls13.TLS13Server;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.RunnerException;

import java.util.concurrent.*;

@State(Scope.Benchmark)
public class TLSBenchmark extends ABenchmark {
  private static Logger logger = Logger.getLogger(TLSBenchmark.class);

  private static Future<Void> mFuture;
  private static AServer mServer;
  private static AClient mClient;

  //----------------- Common ------------------------------
  @Setup(Level.Trial)
  public void setUp() throws Exception {
    HibeCommon.sDebug = true;
    LogManager.shutdown();
  }

  public static abstract class BaseState {
    private static ExecutorService mThreadPool = Executors.newFixedThreadPool(1);

    protected void setup(AServer server, AClient client) throws Exception {
      CountDownLatch gate = new CountDownLatch(1);

      mFuture = mThreadPool.submit(() -> {
        System.out.println("running master server thread!");
        mServer = server;
        gate.countDown();
        mServer.start();
        System.out.println("stop running, returning to pool");
        return null;
      });

      System.out.println("setting up a new client");
      mClient = client;
      mClient.setup(new String[]{});
      logger.info("point compression: " + ECCelerate.isPointCompressionEnabled());


      gate.await();
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
      try {
        mServer.stop();
        mFuture.get(); // waits till thread returns
        System.out.println("Torn down...");
      } finally {
        mThreadPool.shutdownNow();
      }
    }
  }

//
//  //------------- BN_P256 ---------------------------------
//  @State(Scope.Benchmark)
//  public static class State_BN_P256 extends BaseState {
//
//    @Setup(Level.Trial)
//    public void setup() throws Exception {
//      Hibe.sCurve = Hibe.Curve.BN_P256;// TODO find a better way to specify
//      super.setup(new MasterServer(), new MasterClient());
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P256(State_BN_P256 s) throws Exception {
//    mClient.connect();
//  }
//  //------------- BN_P461 ---------------------------------
//  @State(Scope.Benchmark)
//  public static class State_BN_P461 extends BaseState {
//
//    @Setup(Level.Trial)
//    public void setup() throws Exception {
//      Hibe.sCurve = Hibe.Curve.BN_P461;// TODO find a better way to specify
//      super.setup(new MasterServer(), new MasterClient());
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P461(State_BN_P461 s) throws Exception {
//    mClient.connect();
//  }
//
//  //-------------- BN_P638 --------------------------------
//  @State(Scope.Benchmark)
//  public static class State_BN_P638 extends BaseState {
//
//    @Setup(Level.Trial)
//    public void setup() throws Exception {
//      Hibe.sCurve = Hibe.Curve.BN_P638;// TODO find a better way to specify
//      super.setup(new MasterServer(), new MasterClient());
//    }
//  }
//  @Benchmark
//  public void Hibe_BN_P638(State_BN_P638 s) throws Exception {
//    mClient.connect();
//  }
//
//  //----------------- ISO_P512 ----------------------------
//  @State(Scope.Benchmark)
//  public static class State_ISO_P512 extends BaseState {
//
//    @Setup(Level.Trial)
//    public void setup() throws Exception {
//      Hibe.sCurve = Hibe.Curve.ISO_P512;// TODO find a better way to specify
//      super.setup(new MasterServer(), new MasterClient());
//    }
//  }
//  @Benchmark
//  public void Hibe_ISO_P512(State_ISO_P512 s) throws Exception {
//    mClient.connect();
//  }
//
//  //---------------- Ed25519 ------------------------------
//  @State(Scope.Benchmark)
//  public static class State_Ed25519 extends BaseState {
//
//    @Setup(Level.Trial)
//    public void setup() throws Exception {
//      TLS13Client.sCurve = TLS13Client.SignAlgo.Ed25519;
//      super.setup(new TLS13Server(), new TLS13Client());
//    }
//  }
//  @Benchmark
//  public void Ed25519(State_Ed25519 s) throws Exception {
//    mClient.connect();
//  }
//
//  //------------- ECDSA -----------------------------------
//  @State(Scope.Benchmark)
//  public static class State_ECDSA extends BaseState {
//
//    @Setup(Level.Trial)
//    public void setup() throws Exception {
//      TLS13Client.sCurve = TLS13Client.SignAlgo.EcDsa;
//      super.setup(new TLS13Server(), new TLS13Client());
//    }
//  }
//    @Benchmark
//  public void ECDSA(State_ECDSA s) throws Exception {
//    mClient.connect();
//  }


  //------------- RSA -----------------------------------
  @State(Scope.Benchmark)
  public static class State_RSA extends BaseState {

    @Setup(Level.Trial)
    public void setup() throws Exception {
      TLS13Client.sCurve = TLS13Client.SignAlgo.RSA;
      super.setup(new TLS13Server(), new TLS13Client());
    }

  }
  @Benchmark
  public void RSA(State_RSA s) throws Exception {
    mClient.connect();
  }

  public static void main(String[] args) throws RunnerException {
    run(TLSBenchmark.class);
  }
}
