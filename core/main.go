// mccx-core hands a TUN file descriptor to mihomo.
//
// Android gives the fd to the app's VpnService; mihomo wants it as a number in
// its own config, and a descriptor can only cross a process boundary two ways:
// inheritance at exec, or SCM_RIGHTS. Both are used here: the app sends the fd
// over an abstract unix socket, and this process re-execs mihomo with the fd
// placed at 3 (Go's ExtraFiles), which is what the generated config points at.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

func main() {
	// If the app dies, take the engine with it: an orphaned mihomo keeps the
	// TUN fd and the DNS port, and the next connect fails with
	// "listen udp 0.0.0.0:1053: bind: address already in use".
	_, _, _ = syscall.Syscall6(syscall.SYS_PRCTL, 1 /* PR_SET_PDEATHSIG */, uintptr(syscall.SIGTERM), 0, 0, 0, 0)

	mihomo := flag.String("mihomo", "", "path to the mihomo binary")
	config := flag.String("config", "", "path to config.yaml")
	home := flag.String("home", "", "mihomo data directory")
	socket := flag.String("sock", "mccx-core", "abstract socket name to receive the fd on")
	flag.Parse()

	if *mihomo == "" || *config == "" {
		fmt.Fprintln(os.Stderr, "mccx-core: -mihomo and -config are required")
		os.Exit(2)
	}

	fmt.Println("mccx-core: waiting for the app to hand over the tun fd")
	fd, err := receiveFd(*socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mccx-core: receive fd:", err)
		os.Exit(1)
	}
	killLeftoverEngines(*mihomo)

	tun := os.NewFile(uintptr(fd), "tun")
	defer tun.Close()
	fmt.Println("mccx-core: tun fd received, starting mihomo")

	args := []string{"-f", *config}
	if *home != "" {
		args = append([]string{"-d", *home}, args...)
	}
	cmd := exec.Command(*mihomo, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// ExtraFiles[0] becomes fd 3 in the child; the config's tun.file-descriptor
	// must be 3 to match.
	cmd.ExtraFiles = []*os.File{tun}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "mccx-core: start mihomo:", err)
		os.Exit(1)
	}
	fmt.Println("mccx-core: mihomo pid", cmd.Process.Pid)
	defer func() {
		_ = cmd.Process.Kill()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range signals {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Fprintln(os.Stderr, "mccx-core: mihomo exited:", exitErr.ExitCode())
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "mccx-core: wait:", err)
		os.Exit(1)
	}
	fmt.Println("mccx-core: mihomo stopped")
}

// receiveFd binds an abstract unix socket, accepts one connection and returns
// the first descriptor the peer sent with SCM_RIGHTS.
func receiveFd(name string) (int, error) {
	listenFd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(listenFd)

	addr := &syscall.SockaddrUnix{Name: "\x00" + name}
	if err := syscall.Bind(listenFd, addr); err != nil {
		return -1, fmt.Errorf("bind abstract socket %q: %w", name, err)
	}
	if err := syscall.Listen(listenFd, 1); err != nil {
		return -1, err
	}

	conn, _, err := syscall.Accept(listenFd)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(conn)

	buf := make([]byte, 4)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := syscall.Recvmsg(conn, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	if oobn == 0 {
		return -1, fmt.Errorf("no descriptor in the message")
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for i := range msgs {
		fds, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("SCM_RIGHTS carried no descriptors")
}

// killLeftoverEngines reaps engines left behind by a previous run of this app.
// Only processes of our own UID can be signalled, and the launcher itself is
// excluded by its own command line.
func killLeftoverEngines(path string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if bytes.Contains(cmdline, []byte("libmihomo.so")) && !bytes.Contains(cmdline, []byte("libmccxcore.so")) {
			if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
				fmt.Println("mccx-core: killed leftover engine", pid)
			}
		}
	}
}
