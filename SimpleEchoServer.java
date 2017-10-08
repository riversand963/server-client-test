import java.net.*;
import java.io.*;
import java.security.*;
import java.util.*;
import javax.net.*;
import javax.net.ssl.*;

public class SimpleEchoServer {
    private final int mPort;
    private boolean mStopped;
    private ServerSocketFactory mServerSocketFactory;
    private ServerSocket mServerSocket;
    private List<Thread> mWorkerThreads = new ArrayList<>();

    public SimpleEchoServer(int port) {
        mPort = port;
        mStopped = true;
    }
    public void start() throws Exception {
        if (mStopped) {
            mServerSocketFactory = SSLServerSocketFactory.getDefault();
            mServerSocket = mServerSocketFactory.createServerSocket(mPort);
            mStopped = false;
        }
    }
    public void serve() throws Exception {
        if (mStopped) {
            System.out.println("Server not started.");
            return;
        }
        while (true) {
            Socket socket = mServerSocket.accept();
            Worker worker = new Worker(socket);
            Thread thread = new Thread(worker);
            mWorkerThreads.add(thread);
            thread.start();
        }
    }

    public void stop() throws Exception {
        if (!mStopped) {
            mServerSocket.close();
        }
    }

    private static class Worker implements Runnable {
        private Socket mSocket;
        public Worker(Socket socket) {
            mSocket = socket;
        }
        public void run() {
            String inputLine;
            try {
                BufferedReader bufferedReader =
                    new BufferedReader(new InputStreamReader(mSocket.getInputStream()));
                BufferedWriter bufferedWriter =
                    new BufferedWriter(new OutputStreamWriter(mSocket.getOutputStream()));

                while ((inputLine = bufferedReader.readLine()) != null) {
                    System.out.println(inputLine);
                    bufferedWriter.write(inputLine, 0, inputLine.length());
                    bufferedWriter.newLine();
                    bufferedWriter.flush();
                }

                bufferedReader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
