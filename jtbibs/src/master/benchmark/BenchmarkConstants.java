package master.benchmark;

//------------- Benchmark ---------------------------------
public final class BenchmarkConstants {
  /**
   * Number of measurement iterations
   */
  public static final int MEASUREMENT_ITERATIONS = 10;
  /**
   * Time per measurement (in seconds)
   */
  public static final int MEASUREMENT_TIME = 20;

  /**
   * Number of warmup iterations
   */
  public static final int WARMUP_ITERATIONS = 5;
  /**
   * Time per measurement (in seconds)
   */
  public static final int WARMUP_TIME = 10;

  /**
   * Total timeout (in seconds)
   */
  public static final int TIMEOUT_TIME = 75; // in seconds
  /**
   * Wait before making client connect, so that server is ready
   */
  public static long ServerClientWait = 5;
}

//--------------------- TESTING ---------------------------
//public final class BenchmarkConstants {
//  /**
//   * Number of measurement iterations
//   */
//  public static final int MEASUREMENT_ITERATIONS = 1;
//  /**
//   * Time per measurement (in seconds)
//   */
//  public static final int MEASUREMENT_TIME = 1;
//
//  /**
//   * Number of warmup iterations
//   */
//  public static final int WARMUP_ITERATIONS = 1;
//  /**
//   * Time per measurement (in seconds)
//   */
//  public static final int WARMUP_TIME = 1;
//
//  /**
//   * Total timeout (in seconds)
//   */
//  public static final int TIMEOUT_TIME = 5; // in seconds
//  /**
//   * Wait before making client connect, so that server is ready
//   */
//  public static long ServerClientWait = 5;
//}
