package iaik.security.hibe;

import org.apache.log4j.Logger;

import java.security.InvalidAlgorithmParameterException;

public class HIBEInvalidAlgorithmParameterException extends InvalidAlgorithmParameterException {

    private static Logger logger = Logger.getLogger(HIBEInvalidAlgorithmParameterException.class);


    public HIBEInvalidAlgorithmParameterException(String msg) {
        super(msg);
        logger.error(msg);
    }
}
