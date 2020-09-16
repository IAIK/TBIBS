package Entities;

import iaik.security.hibe.HIBEcurve;

public class SecurityParams {
  private HIBEcurve mCurve;

  public SecurityParams() {
  }

  public SecurityParams(HIBEcurve c) {
    mCurve = c;
  }

  public HIBEcurve getCurve() {
    return mCurve;
  }
}
