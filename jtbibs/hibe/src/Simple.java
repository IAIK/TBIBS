import Entities.*;
import HIBE.Hibe;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.field.ExtensionFieldElement;
import iaik.security.ec.math.field.SexticOverQuadraticTowerExtensionField;
import org.apache.log4j.Logger;

public class Simple {
  private static Logger logger = Logger.getLogger(Simple.class);

  public static void main(String[] args) {
    new Simple().main();
  }

  private void main(){
    // Webserver
    Hibe hibeWebserver = new Hibe();
    PublicParams pp = hibeWebserver.setUp(3, new SecurityParams());
    MasterKeyPair mkp = hibeWebserver.keyGen(pp);
    DelegatedSecretKey delSecKey = hibeWebserver.delegation(pp, mkp.secKey, "alberlukas@live.de".getBytes());
    DelegatedSecretKey delSecKey2 = hibeWebserver.delegation(pp, delSecKey,"19-12-2019_12:12:12".getBytes());

    //CDN
    //TODO verify for first two delegations
    Hibe hibeCDN = new Hibe();
    DelegatedSecretKey delSecKey3 = hibeCDN.delegation(pp, delSecKey2, "I am a message that wants to be signed, bla balbal balbalbal".getBytes());

    //Client
    // get random message -> element from target group
    Hibe hibeClient = new Hibe();
//    boolean isWorking = hibeClient.ntProbVerify(pp, mkp.pubKey, delSecKey3);
    boolean isWorking = hibeClient.ntDeterVerify(pp, mkp.pubKey, delSecKey3);
    logger.debug("Is it working? " + isWorking);
  }


}
