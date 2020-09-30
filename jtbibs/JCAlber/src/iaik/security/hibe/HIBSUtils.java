package iaik.security.hibe;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class HIBSUtils {

    public enum EpochGranularity {
        Year,
        Month,
        Day,
        HalfDay,
        Hour,
        Minutes
    }

    public static byte[] getEpoch(EpochGranularity g) throws Exception {
        switch (g) {
            case Year:
                return Instant.now().truncatedTo(ChronoUnit.YEARS).toString().getBytes();
            case Month:
                return Instant.now().truncatedTo(ChronoUnit.MONTHS).toString().getBytes();
            case Day:
                return Instant.now().truncatedTo(ChronoUnit.DAYS).toString().getBytes();
            case HalfDay:
                return Instant.now().truncatedTo(ChronoUnit.HALF_DAYS).toString().getBytes();
            case Minutes:
                return Instant.now().truncatedTo(ChronoUnit.MINUTES).toString().getBytes();
            default:
                throw new Exception("EpochGranularity not supported!");
        }
    }
}
