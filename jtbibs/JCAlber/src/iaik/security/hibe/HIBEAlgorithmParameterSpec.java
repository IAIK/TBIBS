package iaik.security.hibe;

import iaik.security.ssl.ServerNameList;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HIBEAlgorithmParameterSpec implements AlgorithmParameterSpec {

    List<byte[]> mIDs = new ArrayList<>();

    public HIBEAlgorithmParameterSpec() {
    }


    public HIBEAlgorithmParameterSpec addDelegateIDs(byte[]... ids){
        mIDs.addAll(Arrays.asList(ids));
        return this;
    }

    boolean complete() { // check for the case the will need more parameters than IDs
        return mIDs != null;
    }

}
