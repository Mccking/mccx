package com.xehn.warp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * VPN Gate nodes, as the upstream engine reports them.
 *
 * <p>Node list JSON shape: {@code {"nodes":[{id,host,ip,port,proto,cc,country,
 * operator,pingMS,speedBps,latencyMS,class,shared,isp,as}],"fetchedAt":...}}.
 * The self-reported speed is deliberately not trusted; only a measured
 * handshake result is (see {@code EngineService.testNodes}).
 */
public final class VpnGate {

    private VpnGate() {
    }

    public static final class Node {
        public String id = "";
        public String host = "";
        public String ip = "";
        public String proto = "";
        public String cc = "";
        public String country = "";
        public String operator = "";
        public String cls = "unknown";
        public String isp = "";
        public int port;
        public int pingMs;
        public int speedBps;
        public int latencyMs;
        public boolean shared;

        public String label() {
            StringBuilder builder = new StringBuilder();
            if (!country.isEmpty()) {
                builder.append(country);
            } else if (!cc.isEmpty()) {
                builder.append(cc);
            } else {
                builder.append(ip.isEmpty() ? host : ip);
            }
            builder.append(" · ").append(classLabel());
            if (!operator.isEmpty()) {
                builder.append(" · ").append(operator);
            }
            return builder.toString();
        }

        public String classLabel() {
            if ("residential".equals(cls)) {
                return "家宽";
            }
            if ("datacenter".equals(cls)) {
                return "机房";
            }
            return "未知";
        }
    }

    public static List<Node> parse(String json) {
        List<Node> nodes = new ArrayList<Node>();
        if (json == null || json.isEmpty()) {
            return nodes;
        }
        try {
            JSONObject root = new JSONObject(json);
            JSONArray array = root.optJSONArray("nodes");
            if (array == null) {
                return nodes;
            }
            for (int i = 0; i < array.length(); i++) {
                JSONObject o = array.optJSONObject(i);
                if (o == null) {
                    continue;
                }
                Node node = new Node();
                node.id = o.optString("id", "");
                node.host = o.optString("host", "");
                node.ip = o.optString("ip", "");
                node.proto = o.optString("proto", "");
                node.cc = o.optString("cc", "");
                node.country = o.optString("country", "");
                node.operator = o.optString("operator", "");
                node.cls = o.optString("class", "unknown");
                node.isp = o.optString("isp", "");
                node.port = o.optInt("port", 0);
                node.pingMs = o.optInt("pingMS", 0);
                node.speedBps = o.optInt("speedBps", 0);
                node.latencyMs = o.optInt("latencyMS", 0);
                node.shared = o.optBoolean("shared", false);
                if (!node.id.isEmpty()) {
                    nodes.add(node);
                }
            }
        } catch (Exception ignored) {
        }
        // Residential first, then reachable-by-handshake, then everything else.
        Collections.sort(nodes, new Comparator<Node>() {
            public int compare(Node a, Node b) {
                int rankA = rank(a);
                int rankB = rank(b);
                if (rankA != rankB) {
                    return rankA - rankB;
                }
                return a.country.compareTo(b.country);
            }
        });
        return nodes;
    }

    private static int rank(Node node) {
        int rank = 0;
        if (!"residential".equals(node.cls)) {
            rank += 10;
        }
        if (node.latencyMs <= 0) {
            rank += 1;
        }
        return rank;
    }
}
