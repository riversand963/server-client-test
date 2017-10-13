public class KerberosTlsEchoServerProcess {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);
        boolean mutualAuthRequired = Boolean.parseBoolean(args[1]);
        KerberosTlsEchoServer server = new KerberosTlsEchoServer(port);
        cleanupOnShutdown(server);
        server.start();
        server.serve();
    }

    private static void cleanupOnShutdown(KerberosTlsEchoServer server) {
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
