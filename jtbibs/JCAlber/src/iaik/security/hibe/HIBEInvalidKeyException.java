package iaik.security.hibe;

import org.apache.log4j.Logger;

import java.security.InvalidKeyException;

public class HIBEInvalidKeyException extends InvalidKeyException {

    private static Logger logger = Logger.getLogger(HIBEInvalidKeyException.class);

    public HIBEInvalidKeyException(String msg) {
        super(msg);
        logger.error(msg);
    }

    public HIBEInvalidKeyException(String message, Throwable cause) {
        super(message, cause);
        logger.error(message);
    }
}
