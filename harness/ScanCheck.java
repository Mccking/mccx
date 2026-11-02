import com.xehn.warp.Warp;

/** Desktop check of the endpoint ranking: registers a device and picks an edge. */
public final class ScanCheck {

    public static void main(String[] args) throws Exception {
        long started = System.currentTimeMillis();
        Warp.Result result = Warp.generate("wg", 1701, true, null, new Warp.Log() {
            public void log(String line) {
                System.out.println("  " + line);
            }
        });
        long elapsed = System.currentTimeMillis() - started;
        System.out.println("--- picked: " + result.endpoint + "  in " + elapsed + " ms ---");
        if (!result.config.contains("Endpoint = " + result.endpoint)) {
            System.out.println("CONFIG/ENDPOINT MISMATCH");
            System.exit(1);
        }
        System.out.println("SCAN OK");
        System.exit(0);
    }
}

