package master.test;

import master.HibeCommon;
import master.benchmark.tls13.TLS13Client;
import master.benchmark.tls13.TLS13Server;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.junit.*;
import org.junit.rules.TestName;

import java.util.concurrent.*;

import static master.benchmark.BenchmarkConstants.ServerClientWait;

public class TLStest {
  private static Logger logger = Logger.getLogger(TLStest.class);

  private ExecutorService mThreadPool = Executors.newSingleThreadScheduledExecutor();
  private Future<Void> mFuture;

  @Rule
  public TestName mTestName = new TestName();
  private TLS13Client mTc;

  @Before
  public void setup() {
    try {
      CountDownLatch gate = new CountDownLatch(1);
      //config
      HibeCommon.sDebug = true;
      LogManager.shutdown();
      TLS13Client.sCurve = TLS13Client.SignAlgo.EcDsa;


      logger.info("setting up");
      mFuture = mThreadPool.submit(() -> {
        logger.info("running server thread!");
        TLS13Server ts = new TLS13Server();
        gate.countDown();
        ts.start();
        return null;
      });
      mThreadPool.shutdown();

      mTc = new TLS13Client();
      mTc.setup(new String[]{});

      gate.await();
      logger.info("sleeping till setup");
      TimeUnit.SECONDS.sleep(ServerClientWait);
    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail("sleep experienced error");
    }
  }

  @After
  public void tearDown() {
    try {
      if (mThreadPool.isTerminated())
        mFuture.get(); // waits till thread returns
    } catch (ExecutionException | InterruptedException e) {
      e.getCause().printStackTrace();
      Assert.fail("Server thread exception happend");
    }
  }

  @Test
  public void ShouldPass() {
    logger.info("starting: " + mTestName.getMethodName());
    try {
    mTc.connect();
    mTc.connect();
    } catch (Exception e) {
      e.getCause().printStackTrace();
      mThreadPool.shutdownNow();
      Assert.fail("Client thread exception happend");
    }

  }

//  @Test
//  public void WrongEpoch() { //TODO
//    logger.info("starting: " + mTestName.getMethodName());
//    try {
//      MasterClient.main0(new String[]{});
//    } catch (Exception e) {
//      e.printStackTrace();
//    }
//
//  }
//
//  @Test
//  public void WrongDomain() {
//    logger.info("starting: " + mTestName.getMethodName());
//  } //TODO
}
