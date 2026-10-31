package com.xehn.warp;

import com.wireguard.android.backend.Tunnel;

/**
 * The tunnel identity handed to the WireGuard backend. The library only needs a
 * name and a state callback; everything else (TUN, routes, DNS, socket
 * protection) happens inside {@code GoBackend}.
 */
public final class WarpTunnel implements Tunnel {

    public interface Listener {
        void onTunnelState(State state);
    }

    private static final String NAME = "xehn-warp";

    private volatile Listener listener;
    private volatile State state = State.DOWN;

    public WarpTunnel(Listener listener) {
        this.listener = listener;
    }

    /** Re-points the callback when the activity is recreated. */
    public void setListener(Listener newListener) {
        this.listener = newListener;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void onStateChange(State newState) {
        state = newState;
        if (listener != null) {
            listener.onTunnelState(newState);
        }
    }

    public State getState() {
        return state;
    }
}
