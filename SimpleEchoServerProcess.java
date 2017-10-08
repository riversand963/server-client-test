import java.net.*;
import java.io.*;
import java.security.*;
import javax.net.*;
import javax.net.ssl.*;


public class SimpleEchoServerProcess {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        SimpleEchoServer server = new SimpleEchoServer(port);
        cleanupOnShutdown(server);
        server.start();
        server.serve();
    }
    private static void cleanupOnShutdown(SimpleEchoServer server) {
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                if (server != null) {
                    try {
                        server.stop();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        });
    }
}
