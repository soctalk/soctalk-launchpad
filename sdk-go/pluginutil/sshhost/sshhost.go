// Package sshhost wraps golang.org/x/crypto/ssh with the small set of
// operations launchpad provider plugins need to drive a remote host: dialing
// via the operator's ssh-agent, running commands, writing files, checking
// whether a pidfile's process is alive, and shell-escaping arguments.
package sshhost

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// netDial and newAgentClient are thin wrappers kept so the ssh-agent
// dependency stays localized to this package.
func netDial(network, addr string) (net.Conn, error) { return net.Dial(network, addr) }

func newAgentClient(c net.Conn) agent.Agent { return agent.NewClient(c) }

// Dial opens an SSH connection to userHost:port, authenticating with keys held
// by the operator's ssh-agent (SSH_AUTH_SOCK). userHost may be "user@host"; it
// defaults to the root user when no "user@" prefix is present. Host keys are
// not verified.
func Dial(userHost string, port int) (*ssh.Client, error) {
	user := "root"
	host := userHost
	if i := strings.IndexByte(userHost, '@'); i >= 0 {
		user, host = userHost[:i], userHost[i+1:]
	}
	// Rely on the operator's ssh-agent for authentication. Explicit
	// credential handling is out of scope for the plugin.
	// (Callers should have SSH_AUTH_SOCK populated.)
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK is not set; add key with `ssh-add` first")
	}
	agentConn, err := netDial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("dial ssh-agent: %w", err)
	}
	agentCli := newAgentClient(agentConn)
	signers, err := agentCli.Signers()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent signers: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
}

// Run executes cmd on the remote host and returns its combined stdout+stderr.
// It respects ctx cancellation.
func Run(ctx context.Context, c *ssh.Client, cmd string) (string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	// Wire stdout/stderr into a single buffer.
	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()
	select {
	case err := <-done:
		if err != nil {
			return buf.String(), fmt.Errorf("%s: %w: %s", cmd, err, buf.String())
		}
		return buf.String(), nil
	case <-ctx.Done():
		_ = sess.Close()
		return "", ctx.Err()
	}
}

// WriteFile writes content to a remote path by piping it into `cat > path`.
// Simpler than sftp; adequate for user-data ISOs and similar.
func WriteFile(c *ssh.Client, path string, content []byte) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	cmd := "cat > " + ShellEscape(path)
	if err := sess.Start(cmd); err != nil {
		return err
	}
	if _, err := stdin.Write(content); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	return sess.Wait()
}

// PidAlive reports whether the process named by the remote pidPath is alive
// (kill -0 succeeds). A missing pidfile yields (false, nil).
func PidAlive(ctx context.Context, c *ssh.Client, pidPath string) (bool, error) {
	out, err := Run(ctx, c,
		"if [ -f "+ShellEscape(pidPath)+" ]; then kill -0 $(cat "+ShellEscape(pidPath)+") 2>/dev/null && echo yes; fi")
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "yes"), nil
}

// ShellEscape quotes s for safe use as a single shell argument. Strings with no
// shell-special characters are returned unchanged.
func ShellEscape(s string) string {
	if !strings.ContainsAny(s, " '\"$\\`&|;<>*()[]{}?!#~") {
		return s
	}
	// Wrap in single quotes; escape inner single quotes with '\''.
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
