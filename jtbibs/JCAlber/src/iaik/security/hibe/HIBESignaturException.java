package iaik.security.hibe;

import org.apache.log4j.Logger;

import java.security.SignatureException;

public class HIBESignaturException extends SignatureException {

    private static Logger logger = Logger.getLogger(HIBESignaturException.class);


    public HIBESignaturException(String msg) {
        super(msg);
        logger.error(msg);
    }
}
