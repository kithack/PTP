package edu.kit.tm.ptp;

import edu.kit.tm.ptp.auth.EvilPublicKeyAuthenticatorFactory;

/**
 * Creates PTP instance with evil authenticator.
 *
 * @author Timon Hackenjos
 */

public class EvilPTP {
  public static PTP getEvilPTP() {
    PTP ptp = new PTP();
    ptp.authFactory = new EvilPublicKeyAuthenticatorFactory();
    return ptp;
  }
}
