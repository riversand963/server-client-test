import java.io.*;
import java.net.*;
import javax.net.ssl.*;

public class SimpleEchoClient {
    public static void main(String[] args) throws Exception {
        String hostName = args[0];
        int port = Integer.parseInt(args[1]);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(System.in));
        PrintStream out = System.out;
        SSLSocketFactory sslSocketFactory =
            (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket =
            (SSLSocket) sslSocketFactory.createSocket(hostName, port);
        printSocketInfo(socket);

        socket.startHandshake();

        BufferedWriter bufferedWriter =
            new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
        BufferedReader bufferedReader =
            new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String line;
        String response;
        while ((line = in.readLine()) != null) {
            bufferedWriter.write(line, 0, line.length());
            bufferedWriter.newLine();
            bufferedWriter.flush();

            response = bufferedReader.readLine();
            out.println(response);
        }
        bufferedWriter.close();
        bufferedReader.close();
        socket.close();
    }

    private static void printSocketInfo(SSLSocket s) {
        System.out.println("Socket class: "+s.getClass());
        System.out.println("   Remote address = " +s.getInetAddress().toString());
        System.out.println("   Remote port = "+s.getPort());
        System.out.println("   Local socket address = " +s.getLocalSocketAddress().toString());
        System.out.println("   Local address = " +s.getLocalAddress().toString());
        System.out.println("   Local port = "+s.getLocalPort());
        System.out.println("   Need client authentication = " +s.getNeedClientAuth());
        SSLSession ss = s.getSession();
        System.out.println("   Cipher suite = "+ss.getCipherSuite());
        System.out.println("   Protocol = "+ss.getProtocol());
    }
}
