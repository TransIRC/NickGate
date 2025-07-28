package main

import (
        "context"
        "flag"
        "io"
        "log"
        "net"
        "os"
        "os/exec"
        "os/signal"
        "path/filepath"
        "strings"
        "sync"
        "syscall"
        "time"
        "fmt"
        "unsafe"

        "nickgate/config"
        "nickgate/nickserv"

        "github.com/creack/pty"
        "github.com/pires/go-proxyproto"
        "golang.org/x/crypto/ssh"
)

var (
        logFile *os.File
        logger  *log.Logger
)

type Server struct {
        config                  *ssh.ServerConfig
        nsAuth                  *nickserv.AuthClient
        sshPort                 string
        hostKeyFile             string
        forceCmd                string
        forceOnExitCommand      string
        realIPFallback          string
        proxyProtocolEnabled    bool
        proxyAllowedIPs         []net.IPNet
        allowRegistrationOnFail bool           // Store config setting
        loginFailures           map[string]int // Track failures per session
        failuresLock            sync.Mutex     // Mutex for the failure map
}

func initLogging(logPath string) error {
        var err error
        logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                return err
        }
        logger = log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags|log.Lshortfile)
        log.SetOutput(io.MultiWriter(os.Stdout, logFile))
        return nil
}

func NewServer(cfg *config.Config) (*Server, error) {
        if err := initLogging("/var/log/nickgate.log"); err != nil {
                return nil, err
        }

        server := &Server{
                sshPort:                 cfg.SSHPort,
                hostKeyFile:             cfg.HostKeyFile,
                forceCmd:                cfg.ForceCommand,
                forceOnExitCommand:      cfg.ForceOnExitCommand,
                realIPFallback:          cfg.RealIPFallback,
                proxyProtocolEnabled:    cfg.ProxyProtocolEnabled,
                proxyAllowedIPs:         cfg.ProxyAllowedIPs,
                allowRegistrationOnFail: cfg.NickServAPI.AllowRegistrationOnFail, // Initialize from config
                loginFailures:           make(map[string]int),                  // Initialize map
                nsAuth: nickserv.NewAuthClient(
                        cfg.NickServAPI.URL,
                        cfg.NickServAPI.RegisterURL, // <-- Pass register URL here!
                        cfg.NickServAPI.Token,
                ),
        }

        sshConfig := &ssh.ServerConfig{
                PasswordCallback: server.authCallback, // Use our new stateful callback
        }

        hostKeyBytes, err := os.ReadFile(server.hostKeyFile)
        if err != nil {
                logger.Printf("Error reading host key file: %v", err)
                return nil, err
        }
        hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
        if err != nil {
                logger.Printf("Error parsing host key: %v", err)
                return nil, err
        }
        sshConfig.AddHostKey(hostKey)

        server.config = sshConfig
        return server, nil

}

// Renamed and updated the original passwordCallback to handle the new logic
func (s *Server) authCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
        user := conn.User()
        sessionID := string(conn.SessionID())

        // Try to authenticate normally first.
        ok, err := s.nsAuth.Authenticate(user, string(password))
        if err != nil {
                logger.Printf("NickServ auth API error for %s: %v", user, err)
                // Don't leak internal errors to the client, just fail the auth.
        }

        if ok {
                // On success, clear failure count and grant access.
                s.failuresLock.Lock()
                delete(s.loginFailures, sessionID)
                s.failuresLock.Unlock()
                logger.Printf("Authentication successful for user %s", user)
                return &ssh.Permissions{
                        Extensions: map[string]string{
                                "user":        user,
                                "remote-addr": conn.RemoteAddr().String(),
                                "password":    string(password),
                        },
                }, nil
        }

        // Auth failed. Lock, increment, and check failure count.
        s.failuresLock.Lock()
        s.loginFailures[sessionID]++
        failures := s.loginFailures[sessionID]
        s.failuresLock.Unlock()

        logger.Printf("Authentication failed for user %s. Attempt %d.", user, failures)

        // After 2 failed attempts (on the 3rd+), try to register if enabled.
        if s.allowRegistrationOnFail && failures > 2 {
                logger.Printf("Attempting registration for %s after %d failed logins.", user, failures-1)

                regOk, regErr := s.nsAuth.Register(user, string(password))
                if regOk {
                        logger.Printf("Registration successful for new user %s", user)
                        // On successful registration, reset counter and grant access.
                        s.failuresLock.Lock()
                        delete(s.loginFailures, sessionID)
                        s.failuresLock.Unlock()
                        return &ssh.Permissions{
                                Extensions: map[string]string{
                                        "user":        user,
                                        "remote-addr": conn.RemoteAddr().String(),
                                        "password":    string(password),
                                },
                        }, nil
                }
                if regErr != nil {
                        logger.Printf("Registration failed for user %s: %v", user, regErr)
                }
        }
        // Return a generic error to prompt the user to try again.
        return nil, fmt.Errorf("permission denied")
}

func (s *Server) handleConnection(conn net.Conn) {
        defer conn.Close()

        startTime := time.Now()
        remoteAddr := conn.RemoteAddr().String()
        logger.Printf("New connection from %s", remoteAddr)

        // Get the real IP - PROXY protocol is handled at the listener level
        realIP := s.realIPFallback
        if s.proxyProtocolEnabled {
                if proxyConn, ok := conn.(*proxyproto.Conn); ok {
                        // Check if the remote address of the proxy connection is in the allowed list
                        if s.isProxyAllowed(proxyConn.RemoteAddr()) {
                                if header := proxyConn.ProxyHeader(); header != nil {
                                        // Extract only the IP part from the SourceAddr
                                        host, _, err := net.SplitHostPort(header.SourceAddr.String())
                                        if err != nil {
                                                // Fallback if there's an error splitting (e.g., if it's already just an IP)
                                                realIP = header.SourceAddr.String()
                                        } else {
                                                realIP = host
                                        }
                                } else {
                                        logger.Printf("PROXY protocol header not found for allowed IP %s, falling back to %s", remoteAddr, s.realIPFallback)
                                        // If no PROXY header, use the remoteAddr as fallback if it's an allowed source
                                        if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
                                                realIP = host
                                        }
                                }
                        } else {
                                logger.Printf("Ignoring PROXY header from non-allowed IP %s, falling back to %s", remoteAddr, s.realIPFallback)
                                // If not allowed, use the remoteAddr as fallback
                                if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
                                        realIP = host
                                }
                        }
                }
        } else {
                if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
                        realIP = host
                        }
        }

        sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
        if err != nil {
                logger.Printf("SSH handshake failed from %s: %v", remoteAddr, err)
                return
        }
        defer sshConn.Close()

        // Defer cleanup of the session from the failure map.
        defer func() {
                sessionID := string(sshConn.SessionID())
                s.failuresLock.Lock()
                delete(s.loginFailures, sessionID)
                s.failuresLock.Unlock()
                logger.Printf("Cleaned up session data for %s", sessionID)
        }()

        sshConn.Permissions.Extensions["real-ip"] = realIP

        logger.Printf("SSH connection established: user=%s client=%s real_ip=%s version=%s duration=%s",
                sshConn.User(),
                remoteAddr,
                realIP,
                sshConn.ClientVersion(),
                time.Since(startTime))

        go ssh.DiscardRequests(reqs)

        for newChannel := range chans {
                if newChannel.ChannelType() != "session" {
                        newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
                        continue
                }
                go s.handleSession(newChannel, sshConn.Permissions)
        }

}

// The rest of the file (isProxyAllowed, handleSession, etc.) remains unchanged.
// ...

func (s *Server) isProxyAllowed(addr net.Addr) bool {
        if len(s.proxyAllowedIPs) == 0 {
                // If no IPs are specified, allow all (or none, depending on desired default behavior)
                // For this implementation, let's assume if the list is empty, no proxy headers are allowed
                return false
        }

        host, _, err := net.SplitHostPort(addr.String())
        if err != nil {
                // If it's already just an IP (no port), use it directly
                host = addr.String()
        }
        ip := net.ParseIP(host)
        if ip == nil {
                return false
        }

        for _, allowedNet := range s.proxyAllowedIPs {
                if allowedNet.Contains(ip) {
                        return true
                }
        }
        return false
}

func (s *Server) handleSession(newChannel ssh.NewChannel, permissions *ssh.Permissions) {
        channel, requests, err := newChannel.Accept()
        if err != nil {
                logger.Printf("Could not accept channel: %v", err)
                return
        }
        defer channel.Close() // Ensure channel is closed when handleSession exits

        user := permissions.Extensions["user"]
        remoteAddr := permissions.Extensions["remote-addr"]
        password := permissions.Extensions["password"]
        realIP := permissions.Extensions["real-ip"]

        logger.Printf("Starting session for user %s from %s (real IP: %s)", user, remoteAddr, realIP)

        cmd := exec.Command(s.forceCmd)
        cmd.Env = append(os.Environ(),
                "SSH_USER="+user,
                "SSH_CLIENT="+remoteAddr,
                "REAL_IP="+realIP,
                "NICK="+user,
                "PASS="+password,
                "TERM=xterm-256color",
                "LANG=en_US.UTF-8",
        )

        ptmx, err := pty.Start(cmd)
        if err != nil {
                logger.Printf("Failed to start command with PTY: %v", err)
                channel.Close()
                return
        }
        defer ptmx.Close() // Ensure ptmx is closed when handleSession exits

        // Create a context that will be cancelled when either the command exits
        // or the SSH channel/PTY connection breaks.
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel() // Ensure the context is cancelled

        // Goroutine to handle SSH channel requests (pty-req, window-change, shell, exec)
        go func() {
                for req := range requests {
                        switch req.Type {
                        case "pty-req":
                                termLen := req.Payload[3]
                                w, h := parseDims(req.Payload[termLen+4:])
                                SetWinsize(ptmx.Fd(), w, h)
                                req.Reply(true, nil)
                        case "window-change":
                                w, h := parseDims(req.Payload)
                                SetWinsize(ptmx.Fd(), w, h)
                                req.Reply(true, nil)
                        case "shell":
                                logger.Printf("Shell request for user %s", user)
                                req.Reply(true, nil)
                        case "exec":
                                logger.Printf("Exec request for user %s", user)
                                req.Reply(true, nil)
                        default:
                                if req.WantReply {
                                        logger.Printf("Unsupported request type '%s' from %s", req.Type, user)
                                        req.Reply(false, nil)
                                }
                        }
                }
                // If the requests channel closes (client disconnects), cancel the context
                cancel()
        }()

        // Goroutine to copy data from SSH channel to PTY (user input)
        go func() {
                _, err := io.Copy(ptmx, channel)
                if err != nil && err != io.EOF {
                        logger.Printf("Error copying from SSH channel to PTY for user %s: %v", user, err)
                }
                cancel() // Signal that the channel-to-pty copy is done (likely due to channel closure)
        }()

        // Goroutine to copy data from PTY to SSH channel (command output)
        go func() {
                _, err := io.Copy(channel, ptmx)
                if err != nil && err != io.EOF {
                        logger.Printf("Error copying from PTY to SSH channel for user %s: %v", user, err)
                }
                cancel() // Signal that the pty-to-channel copy is done (likely due to channel closure)
        }()

        // Signal handling for the child process
        sigch := make(chan os.Signal, 1)
        signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
        go func() {
                select {
                case sig := <-sigch:
                        if cmd.Process != nil {
                                cmd.Process.Signal(sig)
                        }
                case <-ctx.Done(): // Exit this goroutine if the context is cancelled
                        return
                }
        }()

        // Wait for either the command to finish or the SSH session to end
        select {
        case cmdErr := <-(func() chan error {
                ch := make(chan error, 1)
                go func() {
                        ch <- cmd.Wait() // Wait for the command to exit
                }()
                return ch
        }()):
                // The command exited normally or with an error.
                if cmdErr != nil {
                        logger.Printf("Command finished with error for %s: %v", user, cmdErr)
                } else {
                        logger.Printf("Command completed successfully for %s", user)
                }
        case <-ctx.Done():
                // The SSH channel or PTY connection broke, indicating an unexpected session end.
                logger.Printf("Session for user %s ended unexpectedly (SSH channel or PTY connection closed).", user)
                if cmd.Process != nil {
                        logger.Printf("Attempting to kill forceCmd process (PID: %d) for user %s...", cmd.Process.Pid, user)
                        if err := cmd.Process.Kill(); err != nil {
                                logger.Printf("Failed to kill forceCmd process for %s: %v", user, err)
                        } else {
                                logger.Printf("ForceCmd process for %s killed successfully.", user)
                        }
                }
        }

        signal.Stop(sigch)
        close(sigch)

        // Run forceOnExitCommand in a new goroutine if defined
        if s.forceOnExitCommand != "" {
                go func(cmdStr, nick string) {
                        commandToRun := strings.ReplaceAll(cmdStr, "$NICK", nick)
                        logger.Printf("Running force-on-exit command for %s: %s", nick, commandToRun)

                        parts := strings.Fields(commandToRun)
                        if len(parts) == 0 {
                                logger.Printf("Force-on-exit command is empty after substitution for %s", nick)
                                return
                        }
                        exitCmd := exec.Command(parts[0], parts[1:]...)
                        exitCmd.Env = os.Environ() // Inherit environment variables

                        exitCmd.Stdout = nil // Discard stdout and stderr
                        exitCmd.Stderr = nil

                        if err := exitCmd.Start(); err != nil {
                                logger.Printf("Failed to start force-on-exit command for %s: %v", nick, err)
                                return
                        }
                        logger.Printf("Force-on-exit command started in background for %s (PID: %d)", nick, exitCmd.Process.Pid)
                }(s.forceOnExitCommand, user)
        }
}

func parseDims(b []byte) (width, height uint32) {
        width = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
        height = uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
        return
}

type winsize struct {
        ws_row    uint16
        ws_col    uint16
        ws_xpixel uint16
        ws_ypixel uint16
}

func SetWinsize(fd uintptr, w, h uint32) {
        ws := &winsize{ws_col: uint16(w), ws_row: uint16(h)}
        _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(ws)))
        if errno != 0 {
                logger.Printf("SetWinsize failed: %v", errno)
        }
}

func (s *Server) Start() error {
        listener, err := net.Listen("tcp", ":"+s.sshPort)
        if err != nil {
                logger.Printf("Failed to start listener: %v", err)
                return err
        }
        defer listener.Close()

        var finalListener net.Listener = listener

        if s.proxyProtocolEnabled {
                finalListener = &proxyproto.Listener{Listener: listener}
                defer finalListener.Close()
                logger.Printf("PROXY protocol enabled.")
        } else {
                logger.Printf("PROXY protocol disabled.")
        }

        logger.Printf("Server started on port %s (forcecommand=%s)", s.sshPort, s.forceCmd)

        for {
                conn, err := finalListener.Accept()
                if err != nil {
                        logger.Printf("Connection accept error: %v", err)
                        continue
                }
                go s.handleConnection(conn)
        }
}

func main() {
        var configPath string
        flag.StringVar(&configPath, "config", "", "Path to configuration file")
        flag.Parse()

        if configPath == "" {
                exePath, err := os.Executable()
                if err != nil {
                        log.Fatalf("Failed to get executable path: %v", err)
                }
                configPath = filepath.Join(filepath.Dir(exePath), "nickgate.conf")
        }

        cfg, err := config.Load(configPath)
        if err != nil {
                log.Fatalf("Config load error: %v", err)
        }

        server, err := NewServer(cfg)
        if err != nil {
                log.Fatalf("Server init failed: %v", err)
        }

        if err := server.Start(); err != nil {
                log.Fatalf("Server crashed: %v", err)
        }
}