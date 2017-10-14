import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

public class SaslGssapiTlsEchoClient {
    private static final String MECH = "GSSAPI";
    private static final int PORT = 4568;
    private static final byte[] EMPTY = new byte[0];

    public static void main(String[] args) throws Exception {
        String service = args[0];
        String serverName = args[1];
        PrivilegedExceptionAction action =
            new SaslGssapiTlsEchoClientAction(service, serverName, PORT);
        Jaas.loginAndAction("client", action);
    }

    private static class SaslGssapiTlsEchoClientAction implements PrivilegedExceptionAction {
        private String mService;
        private String mServerName;
        private int mPort;
        private CallbackHandler mCallbackHandler = null;

        public SaslGssapiTlsEchoClientAction(String service, String serverName, int port) {
            mService = service;
            mServerName = serverName;
            mPort = port;
        }

        public Object run() throws Exception {
            // Create application-level connection
            AppConnection conn = new AppConnection(mServerName, mPort);

            HashMap<String,Object> props = new HashMap<String,Object>();
            // Request confidentiality
            props.put(Sasl.QOP, "auth-conf");

            // Create SaslClient to perform authentication
            SaslClient clnt = Sasl.createSaslClient(
                new String[]{MECH}, null, mService, mServerName, props, mCallbackHandler);

            if (clnt == null) {
                throw new Exception(
                    "Unable to find client implementation for " + MECH);
            }

            byte[] response;
            byte[] challenge;

            // Get initial response for authentication
            response = clnt.hasInitialResponse() ?
                clnt.evaluateChallenge(EMPTY) : EMPTY;

            // Send initial response to server
            AppConnection.AppReply reply =
                conn.send(AppConnection.AUTH_CMD, response);

            // Repeat until authentication terminates
            while (!clnt.isComplete() &&
                (reply.getStatus() == AppConnection.AUTH_INPROGRESS ||
                 reply.getStatus() == AppConnection.SUCCESS)) {

                // Evaluate challenge to generate response
                challenge = reply.getBytes();
                response = clnt.evaluateChallenge(challenge);

                if (reply.getStatus() == AppConnection.SUCCESS) {
                    if (response != null) {
                        throw new Exception("Protocol error interacting with SASL");
                    }
                    break;
                }

                // Send response to server and read server's next challenge
                reply = conn.send(AppConnection.AUTH_CMD, response);
            }

            // Check status of authentication
            if (clnt.isComplete() && reply.getStatus() == AppConnection.SUCCESS) {
                System.out.println("Client authenticated.");
            } else {
                throw new Exception("Authentication failed: " +
                    " connection status? " + reply.getStatus());
            }

            String qop = (String) clnt.getNegotiatedProperty(Sasl.QOP);
            System.out.println("Negotiated QOP: " + qop);

            // Try out security layer
            boolean sl = (qop.equals("auth-conf") || qop.equals("auth-int"));

            byte[] msg = "Hello There!".getBytes("UTF-8");
            System.out.println("Sending: " + new String(msg, "UTF-8"));

            byte[] encrypted = (sl ? clnt.wrap(msg, 0, msg.length) : msg);

            reply = conn.send(AppConnection.DATA_CMD, encrypted);

            if (reply.getStatus() == AppConnection.SUCCESS) {
                byte[] encryptedReply = reply.getBytes();

                byte[] clearReply = (sl ? clnt.unwrap(encryptedReply,
                    0, encryptedReply.length) : encryptedReply);

                System.out.println("Received: " + new String(clearReply, "UTF-8"));
            } else {
                System.out.println("Failed exchange: " + reply.getStatus());
            }

            conn.close();

            return null;

        }
    }
}
