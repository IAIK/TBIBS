package iaik.security.hibe;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HIBSAlgorithmParameterSpec implements AlgorithmParameterSpec {

    List<byte[]> mIDs = new ArrayList<>();

    public HIBSAlgorithmParameterSpec() {
    }


    public HIBSAlgorithmParameterSpec addDelegateIDs(byte[]... ids){
        mIDs.addAll(Arrays.asList(ids));
        return this;
    }

    boolean complete() { // check for the case the will need more parameters than IDs
        return mIDs != null;
    }

}
