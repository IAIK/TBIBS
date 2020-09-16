package master.benchmark;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.util.concurrent.TimeUnit;

@Warmup(iterations = BenchmarkConstants.WARMUP_ITERATIONS, time = BenchmarkConstants.WARMUP_TIME, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = BenchmarkConstants.MEASUREMENT_ITERATIONS, time = BenchmarkConstants.MEASUREMENT_TIME, timeUnit = TimeUnit.SECONDS)
@Timeout(time = BenchmarkConstants.TIMEOUT_TIME, timeUnit = TimeUnit.SECONDS)
@Fork(value = 1, jvmArgs = {"-Xms2G", "-Xmx2G"})
//@Fork(value = 1, jvmArgs = {"-Xms2G", "-Xmx2G"})
@Threads(1)
public abstract class ABenchmark {


  protected static void run(final Class<?> c) throws RunnerException {
    long time = System.currentTimeMillis();
    Options opt = new OptionsBuilder()
        .mode(Mode.Throughput)
        .include(c.getName())
        .shouldFailOnError(true)
        .output("Benchmarks/" + c.getSimpleName() + time + ".txt")
//        .shouldDoGC(true) //not good for benchmarks?
        .resultFormat(ResultFormatType.CSV)
        .result("Benchmarks/" + c.getSimpleName() + time + ".csv")
        .build();

    new Runner(opt).run();
  }

}




