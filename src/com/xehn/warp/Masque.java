package com.xehn.warp;

import org.json.JSONObject;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * MASQUE (WARP over HTTP/3 or H2/TCP-443) device registration.
 *
 * <p>The API wants an EC P-256 device, not the curve25519 key the WireGuard
 * path uses. mihomo's masque outbound parses those keys with
 * {@code x509.ParseECPrivateKey} (SEC1) and {@code x509.ParsePKIXPublicKey}
 * (X.509 SPKI), while Java hands out PKCS#8 for private keys — so the PKCS#8
 * wrapper is stripped here before base64.
 */
public final class Masque {

    public static final String SNI = "consumer-masque.cloudflareclient.com";
    public static final String DEFAULT_SERVER = "162.159.198.2";
    public static final int DEFAULT_PORT = 443;

    /** H2 endpoints are whole /24s; the same host answers on several ports. */
    private static final String[] HOSTS_V4 = {
            "162.159.198.1", "162.159.198.2", "162.159.198.3", "162.159.198.4",
            "162.159.199.1", "162.159.199.2",
    };
    private static final String[] HOSTS_V6 = {
            "2606:4700:103::1", "2606:4700:103::2", "2606:4700:104::1", "2606:4700:104::2",
    };
    private static final int[] PORTS = {443, 1701, 500, 4500, 4443, 8443, 8095};
    private static final int PROBE_TIMEOUT_MS = 3000;
    /** The same endpoint answers on one attempt and times out on the next. */
    private static final int PROBE_ATTEMPTS = 3;
    private static final int PROBE_THREADS = 16;

    public interface Log {
        void log(String line);
    }

    /** A reachable (host, port) pair for the H2 transport. */
    public static final class Endpoint {
        public final String host;
        public final int port;

        Endpoint(String host, int port) {
            this.host = host;
            this.port = port;
        }

        public String label() {
            return host + ":" + port;
        }
    }

    /**
     * Finds an endpoint that answers on TCP. Order is the preference order:
     * 443 first, then the ports this device's network is known to pass.
     */
    public static Endpoint pickEndpoint(Log log) {
        // Port-major rounds: try 443 everywhere first, then the ports this
        // network is known to pass. Each host gets PROBE_ATTEMPTS tries, because
        // a single failed connect here is mostly noise, not a dead endpoint.
        for (int port : PORTS) {
            final List<Endpoint> round = new ArrayList<Endpoint>();
            for (String host : HOSTS_V4) {
                round.add(new Endpoint(host, port));
            }
            for (String host : HOSTS_V6) {
                round.add(new Endpoint(host, port));
            }

            ExecutorService pool = Executors.newFixedThreadPool(PROBE_THREADS);
            List<Future<Boolean>> results = new ArrayList<Future<Boolean>>();
            try {
                for (final Endpoint candidate : round) {
                    results.add(pool.submit(new Callable<Boolean>() {
                        public Boolean call() {
                            return reachableWithRetries(candidate);
                        }
                    }));
                }
                pool.shutdown();
                pool.awaitTermination(PROBE_TIMEOUT_MS * PROBE_ATTEMPTS + 2000L, TimeUnit.MILLISECONDS);
                for (int i = 0; i < results.size(); i++) {
                    Future<Boolean> future = results.get(i);
                    if (!future.isDone() || future.isCancelled()) {
                        continue;
                    }
                    try {
                        if (Boolean.TRUE.equals(future.get())) {
                            Endpoint found = round.get(i);
                            if (log != null) {
                                log.log("MASQUE 端点可达：" + found.label());
                            }
                            return found;
                        }
                    } catch (Exception ignored) {
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            } finally {
                pool.shutdownNow();
            }
            if (log != null) {
                log.log("端口 " + port + " 上暂无可达端点，继续下一个端口");
            }
        }
        return null;
    }

    public static boolean reachableWithRetries(Endpoint endpoint) {
        for (int attempt = 0; attempt < PROBE_ATTEMPTS; attempt++) {
            if (reachable(endpoint)) {
                return true;
            }
        }
        return false;
    }
    /** Quick TCP reachability check; TLS is left to mihomo. */
    public static boolean reachable(Endpoint endpoint) {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(endpoint.host, endpoint.port), PROBE_TIMEOUT_MS);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }

    private static final String REG_URL = "https://api.cloudflareclient.com/v0a4471/reg";
    private static final String USER_AGENT = "WARP for Android";
    private static final String CLIENT_VERSION = "a-6.35-4471";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Masque() {
    }

    public static final class Account {
        public String id = "";
        public String token = "";
        /** base64(SEC1 EC private key) — what mihomo parses. */
        public String privateKey = "";
        /** base64(PKIX endpoint public key) — what mihomo parses. */
        public String peerPublicKey = "";
        public String ipv4 = "";
        public String ipv6 = "";

        public boolean usable() {
            return !privateKey.isEmpty() && !peerPublicKey.isEmpty() && !ipv4.isEmpty();
        }

        public String toJson() {
            try {
                JSONObject o = new JSONObject();
                o.put("id", id);
                o.put("token", token);
                o.put("private_key", privateKey);
                o.put("peer_public_key", peerPublicKey);
                o.put("ipv4", ipv4);
                o.put("ipv6", ipv6);
                return o.toString();
            } catch (Exception e) {
                return "";
            }
        }

        public static Account fromJson(String json) {
            if (json == null || json.isEmpty()) {
                return null;
            }
            try {
                JSONObject o = new JSONObject(json);
                Account a = new Account();
                a.id = o.optString("id", "");
                a.token = o.optString("token", "");
                a.privateKey = o.optString("private_key", "");
                a.peerPublicKey = o.optString("peer_public_key", "");
                a.ipv4 = o.optString("ipv4", "");
                a.ipv6 = o.optString("ipv6", "");
                return a.usable() ? a : null;
            } catch (Exception e) {
                return null;
            }
        }
    }

    /** Registers a MASQUE device. Blocking. */
    public static Account register() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        KeyPair pair = generator.generateKeyPair();
        byte[] publicPkix = pair.getPublic().getEncoded();
        byte[] privateSec1 = buildSec1((ECPrivateKey) pair.getPrivate(), (ECPublicKey) pair.getPublic());

        // The first enrolment must look like a stock WireGuard one; the key is a
        // throwaway the API only checks the shape of.
        JSONObject first = new JSONObject();
        first.put("key", base64(randomBytes(32)));
        first.put("install_id", "");
        first.put("fcm_token", "");
        first.put("tos", isoNow());
        first.put("model", "PC");
        first.put("serial_number", base64(randomBytes(8)));
        first.put("os_version", "10");
        first.put("key_type", "curve25519");
        first.put("tunnel_type", "wireguard");
        first.put("locale", "en_US");

        String created = Warp.requestAs("POST", REG_URL, first.toString(), null, USER_AGENT, CLIENT_VERSION);
        JSONObject createdJson = new JSONObject(created);
        String id = createdJson.optString("id", "");
        String token = createdJson.optString("token", "");
        if (id.isEmpty() || token.isEmpty()) {
            throw new IOException("MASQUE 注册响应缺少 id/token");
        }

        JSONObject patch = new JSONObject();
        patch.put("key", base64(publicPkix));
        patch.put("key_type", "secp256r1");
        patch.put("tunnel_type", "masque");
        patch.put("name", "warpscout");

        String enrolled = Warp.requestAs("PATCH", REG_URL + "/" + id, patch.toString(), token, USER_AGENT, CLIENT_VERSION);
        JSONObject root = new JSONObject(enrolled);
        Account account = new Account();
        account.id = id;
        account.token = token;
        account.privateKey = base64(privateSec1);

        JSONObject config = root.optJSONObject("config");
        if (config != null) {
            JSONObject iface = config.optJSONObject("interface");
            if (iface != null) {
                JSONObject addresses = iface.optJSONObject("addresses");
                if (addresses != null) {
                    account.ipv4 = addresses.optString("v4", "");
                    account.ipv6 = addresses.optString("v6", "");
                }
            }
            org.json.JSONArray peers = config.optJSONArray("peers");
            if (peers != null && peers.length() > 0) {
                String pem = peers.getJSONObject(0).optString("public_key", "");
                account.peerPublicKey = base64(pemBody(pem));
            }
        }
        if (!account.usable()) {
            throw new IOException("MASQUE 注册响应缺少 peer 公钥或地址");
        }
        return account;
    }

    // ------------------------------------------------------------- sec1 (P-256)

    /**
     * Builds a full SEC1 ECPrivateKey for P-256.
     *
     * <p>Go's {@code x509.ParseECPrivateKey} needs the curve OID inside the
     * structure; Java's PKCS#8 only carries it in the wrapper, so the key is
     * assembled here: version, scalar, [0] prime256v1 OID, [1] public point.
     */
    static byte[] buildSec1(ECPrivateKey priv, ECPublicKey pub) throws IOException {
        byte[] scalar = fixed(priv.getS(), 32);
        byte[] x = fixed(pub.getW().getAffineX(), 32);
        byte[] y = fixed(pub.getW().getAffineY(), 32);
        byte[] point = new byte[65];
        point[0] = 0x04;
        System.arraycopy(x, 0, point, 1, 32);
        System.arraycopy(y, 0, point, 33, 32);

        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.write(new byte[]{0x02, 0x01, 0x01});                       // version = 1
        inner.write(tlv(0x04, scalar));                                   // privateKey
        inner.write(tlv(0xA0, keyOid()));                                 // [0] parameters
        inner.write(tlv(0xA1, tlv(0x03, bitString(point))));              // [1] publicKey

        return tlv(0x30, inner.toByteArray());
    }

    /** 1.2.840.10045.3.1.7 — prime256v1. */
    private static byte[] keyOid() {
        return new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};
    }

    private static byte[] bitString(byte[] point) {
        byte[] out = new byte[point.length + 1];
        out[0] = 0x00;  // no unused bits
        System.arraycopy(point, 0, out, 1, point.length);
        return out;
    }

    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else if (len <= 0xff) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xff);
            out.write(len & 0xff);
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    private static byte[] fixed(java.math.BigInteger value, int size) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[size];
        int copy = Math.min(raw.length, size);
        System.arraycopy(raw, raw.length - copy, out, size - copy, copy);
        return out;
    }
    // ------------------------------------------------------------------ helpers

    private static byte[] pemBody(String pem) throws IOException {
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return java.util.Base64.getDecoder().decode(body);
    }

    private static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RANDOM.nextBytes(out);
        return out;
    }

    private static String base64(byte[] data) {
        return java.util.Base64.getEncoder().encodeToString(data);
    }

    private static String isoNow() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date());
    }
}





