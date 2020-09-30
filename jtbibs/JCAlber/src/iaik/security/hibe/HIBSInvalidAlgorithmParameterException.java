package iaik.security.hibe;

import org.apache.log4j.Logger;

import java.security.InvalidAlgorithmParameterException;

public class HIBSInvalidAlgorithmParameterException extends InvalidAlgorithmParameterException {

    private static Logger logger = Logger.getLogger(HIBSInvalidAlgorithmParameterException.class);


    public HIBSInvalidAlgorithmParameterException(String msg) {
        super(msg);
        logger.error(msg);
    }
}
