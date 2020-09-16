import org.apache.log4j.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class UtilsTest {
    private static Logger logger = Logger.getLogger(UtilsTest.class);

    @Rule
    public TestName mTestName = new TestName();

    @Before
    public void init() {
        logger.info("setting up");
    }


    @Test
    public void EpochRecov() {
        logger.info("starting: " + mTestName.getMethodName());
        logger.info(Instant.now().truncatedTo(ChronoUnit.DAYS).toString());
        byte[] b = Instant.now().truncatedTo(ChronoUnit.DAYS).toString().getBytes();
        logger.info(new String(b));
        Assert.assertEquals(Instant.now().truncatedTo(ChronoUnit.DAYS).toString(), new String(b));
        Assert.assertEquals(Instant.now().truncatedTo(ChronoUnit.DAYS), Instant.parse(new String(b)));
    }
}
