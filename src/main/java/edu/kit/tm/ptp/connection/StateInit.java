package edu.kit.tm.ptp.connection;

import edu.kit.tm.ptp.Identifier;
import edu.kit.tm.ptp.channels.MessageChannel;

import java.io.IOException;
import java.util.logging.Level;

/**
 * Initial state of a message channel. State transition is triggered by an incoming connection or an
 * outgoing connection attempt. Part of the state pattern.
 * 
 * @author Timon Hackenjos
 *
 */

public class StateInit extends AbstractState {
  public StateInit(Context context) {
    super(context);
  }

  @Override
  public void opened(MessageChannel channel) {
    ConnectionManager manager = context.getConnectionManager();
    // Incoming connection

    if (manager.localIdentifier == null) {
      manager.logger.log(Level.INFO,
          "Closing incoming connection because local identifier isn't set");
      close(channel);
      return;
    }

    try {
      manager.logger.log(Level.INFO, "Received new connection from "
          + channel.getChannel().socket().getRemoteSocketAddress().toString());

      manager.channelManager.addChannel(channel);
    } catch (IOException ioe) {
      manager.logger.log(Level.WARNING, "Failed to get remote address of new channel", ioe);
      close(channel);
      return;
    }

    context.setState(context.getConcreteConnected());

    context.authenticate(channel);
  }

  @Override
  public boolean sendMessage(MessageAttempt attempt) {
    ConnectionManager manager = context.getConnectionManager();

    Identifier identifier = attempt.getDestination();
    MessageChannel channel = null;

    if (manager.localIdentifier == null) {
      manager.logger.log(Level.INFO, "Delaying message attempt because local Identifier isn't set");
      return false;
    }

    if (manager.socksPort == -1 || manager.socksHost == null) {
      manager.logger.log(Level.INFO, "Delaying message attempt because socks proxy isn't set");
      return false;
    }

    manager.logger.log(Level.INFO, "Connection to destination " + identifier + " is closed");
    if (manager.lastTry.get(identifier) == null || System.currentTimeMillis()
        - manager.lastTry.get(identifier) >= manager.connectRetryInterval) {
      manager.logger.log(Level.INFO, "Opening new connection to destination " + identifier);
      manager.lastTry.put(identifier, System.currentTimeMillis());
      try {
        channel = manager.connect(identifier);

        manager.identifierMap.put(identifier, channel);
        manager.channelMap.put(channel, identifier);
        manager.channelContexts.put(channel, context);

        context.setState(context.getConcreteConnect());
      } catch (IOException ioe) {
        manager.logger.log(Level.WARNING,
            "Error while trying to open a new connection to " + identifier, ioe);
      }
    }

    return false;
  }

}
