package unilog

import (
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

// uuidV4 avoids pulling in an external dependency — spec requires zero
// runtime dependencies across all five languages.
func uuidV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012d", os.Getpid())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Resource is a resolved resource block, ready to embed verbatim in every record.
type Resource map[string]any

// ResourceConfig lets callers override resolver output explicitly (highest
// priority source, spec §3.1 step 1).
type ResourceConfig struct {
	ServiceName      string
	ServiceNamespace string
	Environment      string
}

func parseOTelResourceAttributes(raw string) (map[string]string, bool) {
	out := map[string]string{}
	if raw == "" {
		return out, true
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, false
		}
		k, errK := url.QueryUnescape(strings.TrimSpace(kv[0]))
		v, errV := url.QueryUnescape(strings.TrimSpace(kv[1]))
		if errK != nil || errV != nil {
			return nil, false
		}
		out[k] = v
	}
	return out, true
}

func executableBasename() string {
	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}
	return "go"
}

func buildInfoServiceName() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return filepath.Base(info.Main.Path)
}

// commandLine reconstructs "how to run this again": hostname> cd <dir>;
// <argv, with the executable shortened to its basename>. Meant for a human
// staring at a log line to know where to go, not for machine parsing — spec
// deviation V12. Value-pattern redacted like Body, since argv can carry a
// secret (a flag value) the way any other free-form string can.
func commandLine(hostName string) string {
	dir, err := os.Getwd()
	if err != nil {
		dir = "?"
	}
	args := make([]string, len(os.Args))
	copy(args, os.Args)
	if len(args) > 0 {
		args[0] = filepath.Base(args[0])
	}
	host := hostName
	if host == "" {
		host = "?"
	}
	return globalRedactor.RedactValuePatterns(host + "> cd " + dir + "; " + strings.Join(args, " "))
}

func resolveResource(cfg ResourceConfig) Resource {
	otelAttrs, ok := parseOTelResourceAttributes(os.Getenv("OTEL_RESOURCE_ATTRIBUTES"))
	if !ok {
		os.Stderr.WriteString("unilog: OTEL_RESOURCE_ATTRIBUTES is malformed, ignoring it entirely\n")
		otelAttrs = map[string]string{}
	}

	buildName := buildInfoServiceName()

	serviceName := firstNonEmpty(cfg.ServiceName, os.Getenv("OTEL_SERVICE_NAME"), otelAttrs["service.name"], buildName, "unknown_service:"+executableBasename())
	serviceNamespace := firstNonEmpty(cfg.ServiceNamespace, os.Getenv("LOG_SERVICE_NAMESPACE"), otelAttrs["service.namespace"])
	deploymentEnv := firstNonEmpty(cfg.Environment, os.Getenv("LOG_ENV"), otelAttrs["deployment.environment.name"])

	hostName, _ := os.Hostname()

	k8s := map[string]string{}
	for attr, envVar := range map[string]string{
		"k8s.namespace.name":  "K8S_NAMESPACE",
		"k8s.pod.name":        "K8S_POD_NAME",
		"k8s.container.name":  "K8S_CONTAINER_NAME",
		"k8s.node.name":       "K8S_NODE_NAME",
	} {
		if v := os.Getenv(envVar); v != "" {
			k8s[attr] = v
		}
	}

	res := Resource{"service.name": serviceName}
	if serviceNamespace != "" {
		res["service.namespace"] = serviceNamespace
	}
	res["service.instance.id"] = instanceID(k8s, hostName)
	if deploymentEnv != "" {
		res["deployment.environment.name"] = deploymentEnv
	}
	if hostName != "" {
		res["host.name"] = hostName
	}
	if os.Getenv("LOG_RESOURCE_PROCESS") != "0" {
		res["process.pid"] = os.Getpid()
	}
	if os.Getenv("LOG_RESOURCE_COMMAND") != "0" {
		res["command"] = commandLine(hostName)
	}
	for k, v := range k8s {
		res[k] = v
	}
	for k, v := range otelAttrs {
		if _, known := res[k]; !known && k != "service.name" && k != "service.namespace" && k != "deployment.environment.name" {
			res[k] = v
		}
	}
	return res
}

func instanceID(k8s map[string]string, hostName string) string {
	strategy := getenvDefault("LOG_INSTANCE_ID_STRATEGY", "auto")
	switch strategy {
	case "none":
		return ""
	case "host-pid":
		return hostName + "/" + strconv.Itoa(os.Getpid())
	}
	if pod, ok := k8s["k8s.pod.name"]; ok {
		parts := []string{}
		if ns, ok := k8s["k8s.namespace.name"]; ok {
			parts = append(parts, ns)
		}
		parts = append(parts, pod)
		if c, ok := k8s["k8s.container.name"]; ok {
			parts = append(parts, c)
		}
		return strings.Join(parts, ".")
	}
	return uuidV4()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var (
	resourceOnce   sync.Once
	resourceCached Resource
	resourceCfg    ResourceConfig
)

// GetResource returns the process-wide resolved resource, cached after first call.
func GetResource() Resource {
	resourceOnce.Do(func() { resourceCached = resolveResource(resourceCfg) })
	return resourceCached
}

// Configure overrides resource fields explicitly before the first log call.
// Safe to call from an init() that runs before unilog's own init().
func Configure(cfg ResourceConfig) {
	resourceCfg = cfg
}
