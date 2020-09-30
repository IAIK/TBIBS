package iaik.security.hibe;

import org.apache.log4j.Logger;

import java.security.InvalidKeyException;

public class HIBSInvalidKeyException extends InvalidKeyException {

    private static Logger logger = Logger.getLogger(HIBSInvalidKeyException.class);

    public HIBSInvalidKeyException(String msg) {
        super(msg);
        logger.error(msg);
    }

    public HIBSInvalidKeyException(String message, Throwable cause) {
        super(message, cause);
        logger.error(message);
    }
}
