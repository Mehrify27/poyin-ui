//go:build linux

package service

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	awgUserspaceBinName = "amneziawg-go"
	amneziawgSocketDir  = "/var/run/amneziawg"
	awgProcPrefix       = "awg-go-"
)

func awgKernelModuleLoaded() bool {
	return moduleAvailable(amneziawgModule)
}

func awgKernelModuleIsLegacyV1() bool {
	raw, err := os.ReadFile("/sys/module/" + amneziawgModule + "/version")
	if err != nil {
		return false
	}
	v := strings.TrimSpace(string(raw))
	// Older upstream prebuilt packages shipped v1.0.2024xxxx without AWG 1.5/2.0
	// attributes, whereas our bundled module ("1.0.0") and 2025+ releases carry them.
	return strings.HasPrefix(v, "1.0.2024")
}

// awgUserspaceBinPath returns the path to an external amneziawg-go binary if
// bundled or installed on PATH, or "" when only the in-process engine exists.
func awgUserspaceBinPath() string {
	if p := backend.DaemonPath(awgUserspaceBinName); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(awgUserspaceBinName); err == nil {
		return p
	}
	return ""
}

// awgUserspaceAvailable reports whether the userspace AmneziaWG engine (either
// an external amneziawg-go binary or the built-in Go AWG 2.0 TUN engine) can
// run on this Linux host.
func awgUserspaceAvailable() bool {
	if awgUserspaceBinPath() != "" {
		return true
	}
	_, err := os.Stat("/dev/net/tun")
	return err == nil
}

// awgRuntimeBackendSummary returns a human-readable status summary for the
// Core Status panel and logs.
func awgRuntimeBackendSummary() string {
	kLoaded := awgKernelModuleLoaded()
	bin := awgUserspaceBinPath()
	uMode := "built-in userspace AWG 2.0"
	if bin != "" {
		uMode = "amneziawg-go (" + bin + ")"
	} else if !awgUserspaceAvailable() {
		uMode = "userspace unavailable (/dev/net/tun missing)"
	}

	activeUser := awgActiveUserspaceIfaces()
	var parts []string
	if kLoaded {
		parts = append(parts, "kernel("+amneziawgModuleVersion()+")")
	} else {
		parts = append(parts, "kernel(not loaded)")
	}
	parts = append(parts, uMode)
	if len(activeUser) > 0 {
		parts = append(parts, "userspace ifaces: "+strings.Join(activeUser, ", "))
	}
	return strings.Join(parts, "; ")
}

func awgUserspaceLogs() string {
	var b strings.Builder
	if logs := procMgr.LogsByPrefix(awgProcPrefix); logs != "" {
		b.WriteString(logs)
	}
	inprocMgr.mu.Lock()
	for _, name := range inprocMgr.sortedNamesLocked() {
		inst := inprocMgr.instances[name]
		if logs := inst.logs.String(); logs != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString("===== " + awgProcPrefix + name + " (built-in) =====\n")
			b.WriteString(logs)
			b.WriteString("\n")
		}
	}
	inprocMgr.mu.Unlock()
	return b.String()
}

func isAwgUserspaceActive(iface string) bool {
	if procMgr.IsRunning(awgProcPrefix + iface) {
		return true
	}
	return inprocMgr.has(iface)
}

func awgActiveUserspaceIfaces() []string {
	seen := make(map[string]bool)
	for _, name := range procMgr.namesWithPrefix(awgProcPrefix) {
		if procMgr.IsRunning(name) {
			seen[strings.TrimPrefix(name, awgProcPrefix)] = true
		}
	}
	for _, name := range inprocMgr.names() {
		seen[name] = true
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func awgSocketPath(iface string) string {
	return filepath.Join(amneziawgSocketDir, iface+".sock")
}

func awgUserSocketAlive(iface string) bool {
	for _, dir := range []string{amneziawgSocketDir, "/var/run/wireguard"} {
		sock := filepath.Join(dir, iface+".sock")
		conn, err := net.DialTimeout("unix", sock, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// ensureAwgUserspaceInterface ensures the named userspace AmneziaWG TUN device
// and its UAPI UNIX socket are up. Prefers an external amneziawg-go binary when
// present and otherwise launches the built-in Go AWG 2.0 engine.
func ensureAwgUserspaceInterface(iface string, mtu int) error {
	if existing, err := netlink.LinkByName(iface); err == nil {
		if existing.Type() == amneziawgLinkKind {
			_ = netlink.LinkDel(existing)
		} else if awgUserSocketAlive(iface) {
			return nil
		} else {
			// Orphaned non-responsive TUN left over from a crash — recreate cleanly.
			_ = netlink.LinkDel(existing)
			_ = os.Remove(awgSocketPath(iface))
		}
	}

	if bin := awgUserspaceBinPath(); bin != "" {
		if err := os.MkdirAll(amneziawgSocketDir, 0o755); err != nil {
			return err
		}
		_ = os.Remove(awgSocketPath(iface))
		procName := awgProcPrefix + iface
		env := []string{"WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1"}
		if err := procMgr.Start(procName, bin, []string{"-f", iface}, env, ""); err == nil {
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				if awgUserSocketAlive(iface) {
					if l, err := netlink.LinkByName(iface); err == nil && mtu > 0 && l.Attrs().MTU != mtu {
						_ = netlink.LinkSetMTU(l, mtu)
					}
					return nil
				}
				time.Sleep(50 * time.Millisecond)
			}
			_ = procMgr.Stop(procName)
			logger.Warningf("AmneziaWG: external %s for %s did not expose UAPI socket in time; falling back to built-in AWG 2.0 engine", bin, iface)
		} else {
			logger.Warningf("AmneziaWG: external %s start failed (%v); falling back to built-in AWG 2.0 engine", bin, err)
		}
	}

	return inprocMgr.ensure(iface, mtu)
}

func stopAwgUserspaceInterface(iface string) error {
	procMgr.Stop(awgProcPrefix + iface)
	inprocMgr.stop(iface)
	_ = os.Remove(awgSocketPath(iface))
	if l, err := netlink.LinkByName(iface); err == nil {
		if l.Type() != amneziawgLinkKind {
			_ = netlink.LinkDel(l)
		}
	}
	return nil
}

func stopAllAwgUserspaceInterfaces() {
	procMgr.StopByPrefix(awgProcPrefix)
	inprocMgr.stopAll()
	entries, err := os.ReadDir(amneziawgSocketDir)
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".sock") {
				_ = os.Remove(filepath.Join(amneziawgSocketDir, e.Name()))
			}
		}
	}
}

// =============================================================================
// Built-in Go Userspace AmneziaWG 2.0 Engine
// =============================================================================

var inprocMgr = &awgInprocManager{
	instances: make(map[string]*inprocAwgInstance),
}

type awgInprocManager struct {
	mu        sync.Mutex
	instances map[string]*inprocAwgInstance
}

func (m *awgInprocManager) has(iface string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.instances[iface]
	return ok
}

func (m *awgInprocManager) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sortedNamesLocked()
}

func (m *awgInprocManager) sortedNamesLocked() []string {
	out := make([]string, 0, len(m.instances))
	for k := range m.instances {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func (m *awgInprocManager) ensure(iface string, mtu int) error {
	m.mu.Lock()
	inst, exists := m.instances[iface]
	m.mu.Unlock()

	if exists {
		if l, err := netlink.LinkByName(iface); err == nil {
			if mtu > 0 && l.Attrs().MTU != mtu {
				_ = netlink.LinkSetMTU(l, mtu)
			}
			return nil
		}
		m.stop(iface)
	}

	if mtu <= 0 {
		mtu = device.DefaultMTU
	}

	inst, err := startInprocAwgInstance(iface, mtu)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if old, dup := m.instances[iface]; dup {
		m.mu.Unlock()
		inst.close()
		return func() error {
			if old != nil && awgUserSocketAlive(iface) {
				return nil
			}
			return errors.New("concurrent interface creation")
		}()
	}
	m.instances[iface] = inst
	m.mu.Unlock()
	return nil
}

func (m *awgInprocManager) stop(iface string) {
	m.mu.Lock()
	inst, ok := m.instances[iface]
	if ok {
		delete(m.instances, iface)
	}
	m.mu.Unlock()
	if inst != nil {
		inst.close()
	}
}

func (m *awgInprocManager) stopAll() {
	m.mu.Lock()
	all := make([]*inprocAwgInstance, 0, len(m.instances))
	for k, inst := range m.instances {
		all = append(all, inst)
		delete(m.instances, k)
	}
	m.mu.Unlock()
	for _, inst := range all {
		inst.close()
	}
}

type awgLogRing struct {
	mu    sync.Mutex
	lines []string
}

func (r *awgLogRing) add(format string, args ...any) {
	msg := fmt.Sprintf("[%s] "+format, append([]any{time.Now().Format("15:04:05")}, args...)...)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, strings.TrimRight(msg, "\r\n"))
	if len(r.lines) > 200 {
		r.lines = r.lines[len(r.lines)-200:]
	}
}

func (r *awgLogRing) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

type inprocAwgInstance struct {
	iface    string
	tunDev   tun.Device
	bind     *awgObfsBind
	dev      *device.Device
	listener net.Listener
	sockPath string
	logs     *awgLogRing
	closed   atomic.Bool
}

func startInprocAwgInstance(iface string, mtu int) (*inprocAwgInstance, error) {
	if err := os.MkdirAll(amneziawgSocketDir, 0o755); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", amneziawgSocketDir, err)
	}

	tunDev, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("CreateTUN(%s): %w", iface, err)
	}

	bind := newAwgObfsBind()
	logs := &awgLogRing{}
	devLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {},
		Errorf: func(format string, args ...any) {
			logs.add(format, args...)
		},
	}

	dev := device.NewDevice(tunDev, bind, devLogger)
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device up %s: %w", iface, err)
	}

	sockPath := awgSocketPath(iface)
	_ = os.Remove(sockPath)
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		dev.Close()
		return nil, err
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("listen %s: %w", sockPath, err)
	}
	_ = os.Chmod(sockPath, 0o600)

	inst := &inprocAwgInstance{
		iface:    iface,
		tunDev:   tunDev,
		bind:     bind,
		dev:      dev,
		listener: listener,
		sockPath: sockPath,
		logs:     logs,
	}
	logs.add("started built-in AmneziaWG 2.0 userspace interface %s (mtu=%d)", iface, mtu)

	go inst.serveUAPI()
	return inst, nil
}

func (inst *inprocAwgInstance) close() {
	if !inst.closed.CompareAndSwap(false, true) {
		return
	}
	if inst.listener != nil {
		_ = inst.listener.Close()
	}
	if inst.sockPath != "" {
		_ = os.Remove(inst.sockPath)
	}
	if inst.dev != nil {
		inst.dev.Close()
	}
	if l, err := netlink.LinkByName(inst.iface); err == nil {
		_ = netlink.LinkDel(l)
	}
	inst.logs.add("stopped built-in AmneziaWG 2.0 userspace interface %s", inst.iface)
}

func (inst *inprocAwgInstance) serveUAPI() {
	for {
		c, err := inst.listener.Accept()
		if err != nil {
			if !inst.closed.Load() {
				inst.logs.add("UAPI accept error: %v", err)
			}
			return
		}
		go inst.handleUAPIConn(c)
	}
}

func (inst *inprocAwgInstance) handleUAPIConn(c net.Conn) {
	defer c.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))

	for {
		op, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		var errno int64
		switch op {
		case "set=1\n":
			errno = inst.handleUAPISet(rw.Reader)
		case "get=1\n":
			b, rerr := rw.ReadByte()
			if rerr != nil {
				return
			}
			if b != '\n' {
				errno = -int64(unix.EINVAL)
				break
			}
			errno = inst.handleUAPIGet(rw.Writer)
		default:
			inst.logs.add("unknown UAPI operation %q", op)
			return
		}
		fmt.Fprintf(rw.Writer, "errno=%d\n\n", errno)
		if err := rw.Writer.Flush(); err != nil {
			return
		}
	}
}

func (inst *inprocAwgInstance) handleUAPIGet(w *bufio.Writer) int64 {
	var raw bytes.Buffer
	if err := inst.dev.IpcGetOperation(&raw); err != nil {
		var ipcErr *device.IPCError
		if errors.As(err, &ipcErr) {
			return ipcErr.ErrorCode()
		}
		return -int64(unix.EIO)
	}

	obfs := inst.bind.currentObfs()
	obfsLines := buildUAPIObfsLines(obfs)
	insertedObfs := false
	lastHSSecNonZero := false

	scanner := bufio.NewScanner(&raw)
	for scanner.Scan() {
		line := scanner.Text()
		if !insertedObfs && strings.HasPrefix(line, "public_key=") {
			for _, ol := range obfsLines {
				_, _ = w.WriteString(ol)
				_ = w.WriteByte('\n')
			}
			insertedObfs = true
		}

		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			secStr := strings.TrimPrefix(line, "last_handshake_time_sec=")
			lastHSSecNonZero = secStr != "" && secStr != "0"
		} else if line == "last_handshake_time_nsec=0" && lastHSSecNonZero {
			// wgctrl-go/internal/wguser treats LastHandshakeTime as unset unless both
			// sec > 0 and nsec > 0.
			line = "last_handshake_time_nsec=1"
		}

		_, _ = w.WriteString(line)
		_ = w.WriteByte('\n')
	}

	if !insertedObfs {
		for _, ol := range obfsLines {
			_, _ = w.WriteString(ol)
			_ = w.WriteByte('\n')
		}
	}
	return 0
}

func buildUAPIObfsLines(obfs awgObfs) []string {
	lines := []string{
		fmt.Sprintf("jc=%d", obfs.Jc),
		fmt.Sprintf("jmin=%d", obfs.Jmin),
		fmt.Sprintf("jmax=%d", obfs.Jmax),
		fmt.Sprintf("s1=%d", obfs.S1),
		fmt.Sprintf("s2=%d", obfs.S2),
		fmt.Sprintf("s3=%d", obfs.S3),
		fmt.Sprintf("s4=%d", obfs.S4),
	}
	if obfs.H1 != "" {
		lines = append(lines, "h1="+obfs.H1)
	}
	if obfs.H2 != "" {
		lines = append(lines, "h2="+obfs.H2)
	}
	if obfs.H3 != "" {
		lines = append(lines, "h3="+obfs.H3)
	}
	if obfs.H4 != "" {
		lines = append(lines, "h4="+obfs.H4)
	}
	if obfs.I1 != "" {
		lines = append(lines, "i1="+obfs.I1)
	}
	if obfs.I2 != "" {
		lines = append(lines, "i2="+obfs.I2)
	}
	if obfs.I3 != "" {
		lines = append(lines, "i3="+obfs.I3)
	}
	if obfs.I4 != "" {
		lines = append(lines, "i4="+obfs.I4)
	}
	if obfs.I5 != "" {
		lines = append(lines, "i5="+obfs.I5)
	}
	return lines
}

type peerMAC1Update struct {
	key      wgtypes.Key
	remove   bool
	endpoint string
}

func (inst *inprocAwgInstance) handleUAPISet(r *bufio.Reader) int64 {
	var wgConf strings.Builder
	obfs := inst.bind.currentObfs()
	obfsChanged := false

	var newPrivKey *wgtypes.Key
	clearPeers := false
	var peerUpdates []peerMAC1Update
	var curPeer *peerMAC1Update

	flushCurPeer := func() {
		if curPeer != nil {
			peerUpdates = append(peerUpdates, *curPeer)
			curPeer = nil
		}
	}

	inPeerSection := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return -int64(unix.EIO)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return -int64(unix.EINVAL)
		}

		if key == "public_key" {
			inPeerSection = true
		}

		if !inPeerSection {
			handled, perr := applyUAPIObfsKV(&obfs, key, val)
			if perr != nil {
				return -int64(unix.EINVAL)
			}
			if handled {
				obfsChanged = true
				continue
			}
		}

		switch key {
		case "private_key":
			if k, kerr := parseHexKey(val); kerr == nil {
				newPrivKey = &k
			}
		case "replace_peers":
			if val == "true" {
				clearPeers = true
			}
		case "public_key":
			flushCurPeer()
			if k, kerr := parseHexKey(val); kerr == nil {
				curPeer = &peerMAC1Update{key: k}
			}
		case "remove":
			if curPeer != nil && val == "true" {
				curPeer.remove = true
			}
		case "endpoint":
			if curPeer != nil {
				curPeer.endpoint = val
			}
		}

		wgConf.WriteString(line)
		wgConf.WriteByte('\n')
	}
	flushCurPeer()

	var newCodec *awgWireCodec
	if obfsChanged {
		var cerr error
		newCodec, cerr = newAwgWireCodec(obfs)
		if cerr != nil {
			inst.logs.add("rejected obfuscation config: %v", cerr)
			return -int64(unix.EINVAL)
		}
	}

	if wgConf.Len() > 0 {
		if err := inst.dev.IpcSetOperation(strings.NewReader(wgConf.String())); err != nil {
			var ipcErr *device.IPCError
			if errors.As(err, &ipcErr) {
				return ipcErr.ErrorCode()
			}
			return -int64(unix.EIO)
		}
	}

	if newCodec != nil {
		inst.bind.setCodec(newCodec, obfs)
	}
	inst.bind.applyKeyUpdates(newPrivKey, clearPeers, peerUpdates)
	return 0
}

func parseHexKey(hexStr string) (wgtypes.Key, error) {
	var k wgtypes.Key
	raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil || len(raw) != len(k) {
		return k, errors.New("invalid hex key")
	}
	copy(k[:], raw)
	return k, nil
}

func applyUAPIObfsKV(obfs *awgObfs, key, val string) (bool, error) {
	parseInt := func(dst *int) error {
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return errors.New("invalid non-negative integer")
		}
		*dst = n
		return nil
	}
	switch key {
	case "jc":
		return true, parseInt(&obfs.Jc)
	case "jmin":
		return true, parseInt(&obfs.Jmin)
	case "jmax":
		return true, parseInt(&obfs.Jmax)
	case "s1":
		return true, parseInt(&obfs.S1)
	case "s2":
		return true, parseInt(&obfs.S2)
	case "s3":
		return true, parseInt(&obfs.S3)
	case "s4":
		return true, parseInt(&obfs.S4)
	case "h1":
		obfs.H1 = strings.TrimSpace(val)
		return true, nil
	case "h2":
		obfs.H2 = strings.TrimSpace(val)
		return true, nil
	case "h3":
		obfs.H3 = strings.TrimSpace(val)
		return true, nil
	case "h4":
		obfs.H4 = strings.TrimSpace(val)
		return true, nil
	case "i1":
		obfs.I1 = strings.TrimSpace(val)
		return true, nil
	case "i2":
		obfs.I2 = strings.TrimSpace(val)
		return true, nil
	case "i3":
		obfs.I3 = strings.TrimSpace(val)
		return true, nil
	case "i4":
		obfs.I4 = strings.TrimSpace(val)
		return true, nil
	case "i5":
		obfs.I5 = strings.TrimSpace(val)
		return true, nil
	default:
		return false, nil
	}
}

// =============================================================================
// conn.Bind Wrapper with AWG 1.0/1.5/2.0 Wire Framing & MAC1 Support
// =============================================================================

type awgObfsBind struct {
	inner conn.Bind

	codecPtr atomic.Pointer[awgWireCodec]

	mu           sync.RWMutex
	obfs         awgObfs
	haveLocalKey bool
	localMAC1Key [32]byte
	peerMAC1     map[wgtypes.Key][32]byte
	epMAC1       map[string][32]byte
}

func newAwgObfsBind() *awgObfsBind {
	b := &awgObfsBind{
		inner:    conn.NewDefaultBind(),
		peerMAC1: make(map[wgtypes.Key][32]byte),
		epMAC1:   make(map[string][32]byte),
	}
	codec, _ := newAwgWireCodec(awgObfs{})
	b.codecPtr.Store(codec)
	return b
}

func (b *awgObfsBind) currentObfs() awgObfs {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.obfs
}

func (b *awgObfsBind) setCodec(codec *awgWireCodec, obfs awgObfs) {
	b.codecPtr.Store(codec)
	b.mu.Lock()
	b.obfs = obfs
	b.mu.Unlock()
}

func (b *awgObfsBind) applyKeyUpdates(priv *wgtypes.Key, clearPeers bool, updates []peerMAC1Update) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if priv != nil {
		var zero wgtypes.Key
		if *priv == zero {
			b.haveLocalKey = false
			b.localMAC1Key = [32]byte{}
		} else {
			b.haveLocalKey = true
			b.localMAC1Key = ComputeWireGuardMAC1Key(priv.PublicKey())
		}
	}
	if clearPeers {
		clear(b.peerMAC1)
		clear(b.epMAC1)
	}
	for _, u := range updates {
		if u.remove {
			delete(b.peerMAC1, u.key)
			continue
		}
		mk := ComputeWireGuardMAC1Key(u.key)
		b.peerMAC1[u.key] = mk
		if u.endpoint != "" {
			b.epMAC1[u.endpoint] = mk
			if ep, err := b.inner.ParseEndpoint(u.endpoint); err == nil {
				b.epMAC1[ep.DstToString()] = mk
			}
		}
	}
}

func (b *awgObfsBind) lookupPeerMAC1Key(ep conn.Endpoint, inner []byte) ([32]byte, bool) {
	mac1Offset := -1
	switch {
	case len(inner) == awgMsgInitiationSize && binary.LittleEndian.Uint32(inner[:4]) == 1:
		mac1Offset = 116
	case len(inner) == awgMsgResponseSize && binary.LittleEndian.Uint32(inner[:4]) == 2:
		mac1Offset = 60
	default:
		return [32]byte{}, false
	}

	origMAC1 := inner[mac1Offset : mac1Offset+16]
	msgPrefix := inner[:mac1Offset]
	epStr := ""
	if ep != nil {
		epStr = ep.DstToString()
	}

	b.mu.RLock()
	if epStr != "" {
		if key, ok := b.epMAC1[epStr]; ok {
			mac := computeWireGuardMAC1(key, msgPrefix)
			if bytes.Equal(mac[:], origMAC1) {
				b.mu.RUnlock()
				return key, true
			}
		}
	}
	cands := make([][32]byte, 0, len(b.peerMAC1))
	for _, k := range b.peerMAC1 {
		cands = append(cands, k)
	}
	b.mu.RUnlock()

	for _, k := range cands {
		mac := computeWireGuardMAC1(k, msgPrefix)
		if bytes.Equal(mac[:], origMAC1) {
			if epStr != "" {
				b.mu.Lock()
				b.epMAC1[epStr] = k
				b.mu.Unlock()
			}
			return k, true
		}
	}
	return [32]byte{}, false
}

func (b *awgObfsBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, actualPort, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, origFn := range fns {
		fn := origFn
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, rerr := fn(packets, sizes, eps)
			if n <= 0 {
				return n, rerr
			}
			codec := b.codecPtr.Load()
			b.mu.RLock()
			localKey := b.localMAC1Key
			haveKey := b.haveLocalKey
			b.mu.RUnlock()
			if codec == nil {
				return n, rerr
			}
			for idx := 0; idx < n; idx++ {
				sz := sizes[idx]
				if sz <= 0 {
					continue
				}
				decoded, ok := codec.DecodeIncoming(packets[idx][:sz], localKey, haveKey)
				if !ok {
					sizes[idx] = 0
					continue
				}
				if len(decoded) > len(packets[idx]) {
					sizes[idx] = 0
					continue
				}
				copy(packets[idx], decoded)
				sizes[idx] = len(decoded)
			}
			return n, rerr
		}
	}
	return wrapped, actualPort, nil
}

func (b *awgObfsBind) Close() error {
	return b.inner.Close()
}

func (b *awgObfsBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

func (b *awgObfsBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	codec := b.codecPtr.Load()
	if codec == nil {
		return b.inner.Send(bufs, ep)
	}

	batchMax := b.inner.BatchSize()
	if batchMax <= 0 {
		batchMax = 1
	}

	if len(bufs) > 0 && len(bufs[0]) >= 4 && binary.LittleEndian.Uint32(bufs[0][:4]) == 1 {
		if preamble := codec.BuildHandshakePreamble(time.Now()); len(preamble) > 0 {
			for start := 0; start < len(preamble); start += batchMax {
				end := start + batchMax
				if end > len(preamble) {
					end = len(preamble)
				}
				if err := b.inner.Send(preamble[start:end], ep); err != nil {
					return err
				}
			}
		}
	}

	encoded := make([][]byte, len(bufs))
	for i, pkt := range bufs {
		encoded[i] = codec.EncodeOutgoing(pkt, func(inner []byte) ([32]byte, bool) {
			return b.lookupPeerMAC1Key(ep, inner)
		})
	}
	for start := 0; start < len(encoded); start += batchMax {
		end := start + batchMax
		if end > len(encoded) {
			end = len(encoded)
		}
		if err := b.inner.Send(encoded[start:end], ep); err != nil {
			return err
		}
	}
	return nil
}

func (b *awgObfsBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *awgObfsBind) BatchSize() int {
	return b.inner.BatchSize()
}

// isAwgKernelUnsupportedError reports whether an error came from a missing or
// older kernel module lacking AWG or AWG 1.5/2.0 features, so callers in auto
// mode can fall back cleanly to the userspace engine.
func isAwgKernelUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ERANGE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "operation not supported") ||
		strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "invalid argument")
}
