package proxy

const (
	DefaultHost     = "0.0.0.0"
	DefaultPort     = "10998"
	DefaultHashType = "sha256"
	DefaultKeysDir  = ".keys"
	TestPort        = "0"
)

type ProxyConfig struct {
	InternalProxyEnabled    bool
	ListenHost              string
	ListenPort              string
	AllowBadFilePermissions bool
	KeysDirectory           string
}

func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		// Default Monax keys port
		InternalProxyEnabled:    true,
		AllowBadFilePermissions: false,
		ListenHost:              DefaultHost,
		ListenPort:              DefaultPort,
		KeysDirectory:           DefaultKeysDir,
	}
}
