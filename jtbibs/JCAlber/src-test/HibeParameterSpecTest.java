package demo;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;

public class HibeParameterSpecTest {
  private static Logger logger = Logger.getLogger(HibeParameterSpecTest.class);

  @Rule
  public TestName mTestName = new TestName();

  @Before
  public void before() {
  }
}
