import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.security.UserGroupInformation;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivilegedExceptionAction;
import java.util.Date;
import java.util.HashMap;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class SimpleCacheServer {
    private static final String MECH = "GSSAPI"; // SASL name for GSS-API/Kerberos
    private static final int PORT = 4568;
    private static final int LOOP_LIMIT = 1;
    private static int sLoopCount = 0;

	public static void main(String[] args) throws Exception {
        PrivilegedExceptionAction<Object> action =
            new SaslServerAction(args[0], args[1], PORT);

        Jaas.loginAndAction("server", action);
	}

    private static void listStatus() {
        Configuration conf = new Configuration();
        conf.set("fs.defaultFS", "hdfs://localhost:9000/alluxio");
        conf.set("hadoop.security.authentication", "kerberos");

        UserGroupInformation.setConfiguration(conf);
        try {
            UserGroupInformation.loginUserFromKeytab("alluxio/localhost@ALLUXIO.COM", "/etc/alluxio/conf/alluxio.keytab");
        } catch (IOException e) {
            System.err.println("Login failed.");
            System.exit(1);
        }
        FileSystem fs;
        try {
            fs = FileSystem.get(conf);
        } catch (IOException e) {
            fs = null;
            System.err.println("Create to create file system client.");
            System.exit(2);
        }
        try {
            FileStatus[] fsStatus = fs.listStatus(new Path("/"));
        } catch (FileNotFoundException e) {
            System.err.println(e.getMessage());
            System.err.println("File not found.");
            System.exit(3);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.err.println("Failed to list files.");
            System.exit(4);
        }
    }

	static class SaslServerAction implements PrivilegedExceptionAction<Object> {
		private String mService;      // used for SASL authentication
        private String mServerName;   // named used for SASL authentication
        private int mLocalPort;
        private CallbackHandler mCallbackHandler = new TestCallbackHandler();

        SaslServerAction(String service, String serverName, int port) {
            mService = service;
            mServerName = serverName;
            mLocalPort = port;
        }

        public Object run() throws Exception {
            ServerSocket ss = new ServerSocket(mLocalPort);

            HashMap<String,Object> props = new HashMap<String,Object>();
            props.put(Sasl.QOP, "auth");

            // Loop, accepting requests from any client
            while (sLoopCount++ < LOOP_LIMIT) {
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

                byte[] msg = conn.receive(AppConnection.DATA_CMD);

                System.out.println("Received: " + new String(msg, "UTF-8"));

                // Construct reply to send to client
                String now = new Date().toString();
                byte[] nowBytes = now.getBytes("UTF-8");
                int len = msg.length + 1 + nowBytes.length;
                byte[] reply = new byte[len];
                System.arraycopy(msg, 0, reply, 0, msg.length);
                reply[msg.length] = ' ';
                System.arraycopy(nowBytes, 0, reply, msg.length+1, nowBytes.length);

                System.out.println("Sending: " + new String(reply, "UTF-8"));

                listStatus();

                conn.send(AppConnection.SUCCESS, reply);
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