import HIBE.Hibe;
import iaik.security.ec.provider.ECCelerate;
import master.HibeCommon;
import master.MasterClient;
import master.MasterServer;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.junit.*;
import org.junit.rules.TestName;

import java.util.concurrent.*;

import static master.benchmark.BenchmarkConstants.ServerClientWait;

public class MasterTest {
  private static Logger logger = Logger.getLogger(MasterTest.class);

  private ExecutorService mThreadPool = Executors.newSingleThreadScheduledExecutor();
  private Future<Void> mFuture;

  @Rule
  public TestName mTestName = new TestName();
  private MasterClient mMc;
  private MasterServer mMs;

  @Before
  public void setup() {
    logger.info("setting up");
    try {
      CountDownLatch gate = new CountDownLatch(1);
//      HibeCommon.sDebug = false;
//      LogManager.shutdown();

      Hibe.sCurve = Hibe.Curve.BN_P638;

      mFuture = mThreadPool.submit(() -> {
        System.out.println("running server thread!");
        mMs = new MasterServer();
        gate.countDown();
        System.out.println("counted down");
        mMs.start();
        return null;
      });

      mMc = new MasterClient();
      mMc.setup(new String[]{});
      logger.info("point compression: " + ECCelerate.isPointCompressionEnabled());

      gate.await();
      System.out.println("past gate");
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
      mMc.connect();
      mMc.connect();
      mMc.connect();
      mMc.connect();
    } catch (Exception e) {
      e.printStackTrace();
      Assert.fail("Client exception happend");
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
