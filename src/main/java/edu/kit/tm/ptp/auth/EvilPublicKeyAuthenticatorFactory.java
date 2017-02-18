package edu.kit.tm.ptp.auth;

import edu.kit.tm.ptp.channels.MessageChannel;
import edu.kit.tm.ptp.connection.ConnectionManager;

/**
 * @author Timon Hackenjos
 */

public class EvilPublicKeyAuthenticatorFactory extends AuthenticatorFactory {
  @Override
  public Authenticator createInstance(ConnectionManager manager, AuthenticationListener listener,
                                      MessageChannel channel) {
    return new EvilPublicKeyAuthenticator(listener, channel, manager.getCryptHelper());
  }
}
