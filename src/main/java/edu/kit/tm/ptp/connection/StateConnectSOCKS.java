package edu.kit.tm.ptp.connection;

import edu.kit.tm.ptp.Identifier;
import edu.kit.tm.ptp.channels.MessageChannel;

import java.util.logging.Level;

/**
 * State of a channel which is successfully connected
 * to the tor socks proxy and tries to connect to a
 * hidden service.
 * A state transition is triggered by a successful connect
 * to the hidden service.
 * 
 * @author Timon Hackenjos
 *
 */

public class StateConnectSOCKS extends AbstractState {
  public StateConnectSOCKS(Context context) {
    super(context);
  }

  @Override
  public void opened(MessageChannel channel) {
    ConnectionManager manager = context.getConnectionManager();
    
    Identifier identifier = manager.channelMap.get(channel);
    
    manager.logger.log(Level.INFO,
        "Connection to " + identifier + " through socks was successfull");

    if (manager.localIdentifier == null) {
      manager.logger.log(Level.WARNING, "No identifier set. Unable to authenticate the connection");
      close(channel);
      return;
    }
    
    context.setState(context.getConcreteConnected());

    manager.logger.log(Level.INFO, "Trying to authenticate connection to " + identifier);
    context.authenticate(channel);
  }

}
