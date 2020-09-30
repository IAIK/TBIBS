package iaik.security.hibe;

import org.apache.log4j.Logger;

import java.security.SignatureException;

public class HIBSSignaturException extends SignatureException {

    private static Logger logger = Logger.getLogger(HIBSSignaturException.class);


    public HIBSSignaturException(String msg) {
        super(msg);
        logger.error(msg);
    }
}
