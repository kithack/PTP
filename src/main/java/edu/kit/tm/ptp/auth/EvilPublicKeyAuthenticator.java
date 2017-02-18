package edu.kit.tm.ptp.auth;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import edu.kit.tm.ptp.Identifier;
import edu.kit.tm.ptp.channels.MessageChannel;
import edu.kit.tm.ptp.crypt.CryptHelper;
import edu.kit.tm.ptp.serialization.Serializer;

/**
 * @author Timon Hackenjos
 */

public class EvilPublicKeyAuthenticator extends PublicKeyAuthenticator {
  private static final Logger logger = Logger.getLogger(PublicKeyAuthenticator.class.getName());
  private static Serializer serializer = null;
  private static AuthenticationMessage authMessage = null;
  private Identifier destination;

  public EvilPublicKeyAuthenticator(AuthenticationListener listener, MessageChannel channel, CryptHelper cryptHelper) {
    super(listener, channel, cryptHelper);
    initSerializer();
  }

  private static void initSerializer() {
    if (serializer == null) {
      serializer = new Serializer();
      serializer.registerClass(Identifier.class);
      serializer.registerClass(byte[].class);
      serializer.registerClass(AuthenticationMessage.class);
    }
  }

  @Override
  public void messageSent(long id, MessageChannel destination) {
    logger.log(Level.WARNING, "Faked auth message has been sent");
  }

  @Override
  public void messageReceived(byte[] data, MessageChannel source) {
    if (data.length == 1 && data[0] == 0x0) {
      authListener.authenticationSuccess(source, destination);
      return;
    }
    AuthenticationMessage authMessage;

    // deserialize received message
    try {
      authMessage = deserialize(data);

      synchronized (EvilPublicKeyAuthenticator.class) {
        this.authMessage = authMessage;
      }
      logger.log(Level.WARNING, "Saving received auth message from " + authMessage.source);
    } catch (IOException e) {
      logger.log(Level.INFO, "Unable to deserialize received authentication message");
    }

    authListener.authenticationFailed(source);
  }

  @Override
  public void authenticate(Identifier own) {
  }

  @Override
  public void authenticate(Identifier own, Identifier other) {
    synchronized (EvilPublicKeyAuthenticator.class) {
      if (authMessage == null) {
        authListener.authenticationFailed(channel);
        return;
      }
      destination = other;

      AuthenticationMessage fake = new AuthenticationMessage(authMessage.source, other,
          authMessage.pubKey, authMessage.timestamp, authMessage.signature);

      sendAuthMessage(fake);
    }
  }

  private void sendAuthMessage(AuthenticationMessage message) {
    byte[] data = serializer.serialize(message);
    channel.addMessage(data, 0);
  }

  private AuthenticationMessage deserialize(byte[] data) throws IOException {
    Object message = serializer.deserialize(data);

    if (!(message instanceof AuthenticationMessage)) {
      logger.log(Level.INFO, "Received invalid message");
      return null;
    } else {
      return (AuthenticationMessage) message;
    }
  }
}
