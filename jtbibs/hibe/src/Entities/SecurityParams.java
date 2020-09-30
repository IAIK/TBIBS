package Entities;

import iaik.security.hibe.HIBScurve;

public class SecurityParams {
  private HIBScurve mCurve;

  public SecurityParams() {
  }

  public SecurityParams(HIBScurve c) {
    mCurve = c;
  }

  public HIBScurve getCurve() {
    return mCurve;
  }
}
