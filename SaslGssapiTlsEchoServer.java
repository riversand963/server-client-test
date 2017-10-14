import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivilegedExceptionAction;
import java.util.Date;
import java.util.HashMap;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;


public class SaslGssapiTlsEchoServer {
    private static final String MECH = "GSSAPI";
    private static final int PORT = 4568;
    private static final int LOOP_LIMIT = 1;
    private static int loopCount = 0;

    public static void main(String[] args) throws Exception {
        String service = args[0];
        String serverName = args[1];
        PrivilegedExceptionAction action =
            new SaslGssapiTlsEchoServerAction(service, serverName, PORT);
        Jaas.loginAndAction("server", action);
    }

    private static class SaslGssapiTlsEchoServerAction implements PrivilegedExceptionAction {
        private String mService;
        private String mServerName;
        private int mPort;
        private CallbackHandler mCallbackHandler = new TestCallbackHandler();
        private ServerSocketFactory mServerSocketFactory;
        private ServerSocket mServerSocket;

        public SaslGssapiTlsEchoServerAction(String service, String serverName, int port) {
            mService = service;
            mServerName = serverName;
            mPort = port;
        }

        public Object run() throws Exception {
            ServerSocket ss = new ServerSocket(mPort);

            HashMap<String,Object> props = new HashMap<String,Object>();
            props.put(Sasl.QOP, "auth-conf,auth-int,auth");

            // Loop, accepting requests from any client
            while (loopCount++ < LOOP_LIMIT) {
                System.out.println("Waiting for incoming connection...");
                Socket socket = ss.accept();

                // Create application-level connection to handle request
                AppConnection conn = new AppConnection(socket);

                // Normally, the application protocol will negotiate which
                // SASL mechanism to use. In this simplified example, we
                // will always use "GSSAPI", the name of the mechanism that does
                // Kerberos via GSS-API

                // Create SaslServer to perform authentication
                SaslServer srv = Sasl.createSaslServer(MECH,
                    mService, mServerName, props, mCallbackHandler);

                if (srv == null) {
                    throw new Exception(
                        "Unable to find server implementation for " + MECH);
                }

                boolean auth = false;

                // Read initial response from client
                byte[] response = conn.receive(AppConnection.AUTH_CMD);
                AppConnection.AppReply clientMsg;

                while (!srv.isComplete()) {
                    try {
                        // Generate challenge based on response
                        byte[] challenge = srv.evaluateResponse(response);

                        if (srv.isComplete()) {
                            conn.send(AppConnection.SUCCESS, challenge);
                            auth = true;
                        } else {
                            clientMsg = conn.send(AppConnection.AUTH_INPROGRESS,
                                challenge);
                            response = clientMsg.getBytes();
                        }
                    } catch (SaslException e) {
                        // e.printStackTrace();
                        // Send failure notification to client
                        conn.send(AppConnection.FAILURE, null);
                        break;
                    }
                }

                // Check status of authentication
                if (srv.isComplete() && auth) {
                    System.out.print("Client authenticated; ");
                    System.out.println("authorized client is: " +
                        srv.getAuthorizationID());
                } else {
                    // Go get another client
                    System.out.println("Authentication failed. ");
                    continue;
                }

                String qop = (String) srv.getNegotiatedProperty(Sasl.QOP);
                System.out.println("Negotiated QOP: " + qop);

                // Now try to use security layer
                boolean sl = (qop.equals("auth-conf") || qop.equals("auth-int"));

                byte[] msg = conn.receive(AppConnection.DATA_CMD);
                byte[] realMsg = (sl ? srv.unwrap(msg, 0, msg.length) : msg);

                System.out.println("Received: " + new String(realMsg, "UTF-8"));

                // Construct reply to send to client
                String now = new Date().toString();
                byte[] nowBytes = now.getBytes("UTF-8");
                int len = realMsg.length + 1 + nowBytes.length;
                byte[] reply = new byte[len];
                System.arraycopy(realMsg, 0, reply, 0, realMsg.length);
                reply[realMsg.length] = ' ';
                System.arraycopy(nowBytes, 0, reply, realMsg.length+1,
                    nowBytes.length);

                System.out.println("Sending: " + new String(reply, "UTF-8"));

                byte[] realReply = (sl ? srv.wrap(reply, 0, reply.length) : reply);

                conn.send(AppConnection.SUCCESS, realReply);
            }
            return null;
        }
    }

    static class TestCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks)
            throws UnsupportedCallbackException {

            AuthorizeCallback acb = null;

            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof AuthorizeCallback) {
                    acb = (AuthorizeCallback) callbacks[i];
                } else {
                    throw new UnsupportedCallbackException(callbacks[i]);
                }
            }

            if (acb != null) {
                String authid = acb.getAuthenticationID();
                String authzid = acb.getAuthorizationID();
                if (authid.equals(authzid)) {
                    // Self is always authorized
                    acb.setAuthorized(true);

                } else {
                    // Should check some database for mapping and decide.
                    // Current simplified policy is to reject authzids that
                    // don't match authid

                    acb.setAuthorized(false);
                }

                if (acb.isAuthorized()) {
                    // Set canonicalized name.
                    // Should look up database for canonical names

                    acb.setAuthorizedID(authzid);
                }
            }
        }
    }
}
