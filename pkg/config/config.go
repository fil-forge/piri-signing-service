package config

import (
	"crypto/ecdsa"
	crypto_ed25519 "crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	ucantodid "github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/principal/signer"
	"github.com/spf13/viper"
)

const (
	// Default values - only host and port have defaults
	DefaultHost = "localhost"
	DefaultPort = 7446

	// Environment variable prefix
	EnvPrefix = "SIGNING_SERVICE"

	// Config file name (without extension)
	ConfigFileName = "signer"
)

type Config struct {
	Host                    string `mapstructure:"host"`
	Port                    int    `mapstructure:"port"`
	RPCUrl                  string `mapstructure:"rpc_url"`
	ServiceContractAddress  string `mapstructure:"service_contract_address"`
	ServiceKey              string `mapstructure:"service_key"`
	ServiceKeyFile          string `mapstructure:"service_key_file"`
	ServiceDID              string `mapstructure:"service_did"`
	SigningKey              string `mapstructure:"signing_key"`
	SigningKeyPath          string `mapstructure:"signing_key_path"`
	SigningKeystorePath     string `mapstructure:"signing_keystore_path"`
	SigningKeystorePassword string `mapstructure:"signing_keystore_password"`
}

// InitViper initializes Viper with defaults and binds it to Cobra flags
func Init() error {
	// Set up environment variables
	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set up config file
	viper.SetConfigName(ConfigFileName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".") // Look in current directory

	// Try to read config file (don't fail if not found)
	if err := viper.ReadInConfig(); err != nil {
		// It's OK if the config file doesn't exist
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			// But return other errors (like parse errors)
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	return nil
}

// Load reads configuration from viper and validates it
func Load() (*Config, error) {
	var cfg Config

	// Unmarshal config from viper
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks that required configuration fields are set
func (c *Config) Validate() error {
	// Host and port have defaults, so they should always be set
	if c.Host == "" {
		return fmt.Errorf("host is required")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	// These fields are required and have no defaults
	if c.RPCUrl == "" {
		return fmt.Errorf("rpc_url is required (set via flag --rpc-url, env SIGNING_SERVICE_RPC_URL, or in signer.yaml)")
	}

	if c.ServiceContractAddress == "" {
		return fmt.Errorf("service_contract_address is required (set via flag --contract-address, env SIGNING_SERVICE_SERVICE_CONTRACT_ADDRESS, or in signer.yaml)")
	}

	if !common.IsHexAddress(c.ServiceContractAddress) {
		return fmt.Errorf("invalid contract address: %s", c.ServiceContractAddress)
	}

	// mutually exclusive configuration values
	if c.ServiceKey != "" && c.ServiceKeyFile != "" {
		return fmt.Errorf("only one of service_key or service_key_file can be specified")
	}
	// If using service key or service key file, a did web is required
	if c.ServiceKey != "" || c.ServiceKeyFile != "" {
		if c.ServiceDID == "" {
			return fmt.Errorf("service_did is required when using service_key or service_key_file")
		}

		if !strings.HasPrefix(c.ServiceDID, "did:web:") {
			return fmt.Errorf("service_did must be a did:web")
		}
	}

	// Must have either signing key, signing key file or keystore
	if c.SigningKey == "" && c.SigningKeyPath == "" && c.SigningKeystorePath == "" {
		return fmt.Errorf("either signing_key, signing_key_path or signing_keystore_path must be provided (set via flags, env vars, or in signer.yaml)")
	}

	// If using keystore, password is required
	if c.SigningKeystorePath != "" && c.SigningKeystorePassword == "" {
		return fmt.Errorf("signing_keystore_password is required when using signing_keystore_path")
	}

	return nil
}

// ContractAddr returns the contract address as a common.Address
func (c *Config) ContractAddr() common.Address {
	return common.HexToAddress(c.ServiceContractAddress)
}

// LoadServiceIdentity loads a multibase-encoded service key string
// and wraps it in a signer along a DID
func LoadServiceIdentity(key string, did string) (principal.Signer, error) {
	k, err := ed25519.Parse(key)
	if err != nil {
		return nil, fmt.Errorf("parsing service key: %w", err)
	}

	d, err := ucantodid.Parse(did)
	if err != nil {
		return nil, fmt.Errorf("parsing service DID: %w", err)
	}

	s, err := signer.Wrap(k, d)
	if err != nil {
		return nil, fmt.Errorf("wrapping service key: %w", err)
	}

	return s, nil
}

// LoadServiceIdentityFromFile loads an Ed25519 private key from a PKCS#8 PEM file
// and wraps it in a signer along a DID
func LoadServiceIdentityFromFile(keyFilePath string, did string) (principal.Signer, error) {
	k, err := SignerFromEd25519PEMFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("loading service key from PEM file: %w", err)
	}

	d, err := ucantodid.Parse(did)
	if err != nil {
		return nil, fmt.Errorf("parsing service DID: %w", err)
	}

	s, err := signer.Wrap(k, d)
	if err != nil {
		return nil, fmt.Errorf("wrapping service key: %w", err)
	}

	return s, nil
}

// SignerFromEd25519PEMFile loads an Ed25519 private key from a PKCS#8 PEM file.
func SignerFromEd25519PEMFile(path string) (principal.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %w", err)
	}
	defer f.Close()

	pemData, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var privateKey *crypto_ed25519.PrivateKey
	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type == "PRIVATE KEY" {
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
			}

			key, ok := parsedKey.(crypto_ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is not an Ed25519 private key")
			}
			privateKey = &key
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("no PRIVATE KEY block found in PEM file")
	}

	// ucantone's FromRaw wants the 32-byte seed; crypto/ed25519.PrivateKey is
	// 64 bytes (seed || pub), so extract the seed before handing it over.
	return ed25519.FromRaw(privateKey.Seed())
}

// LoadSigningKey loads a signing key from a string
// The byte slice can contain either hex-encoded or raw bytes
func LoadSigningKey(data string) (*ecdsa.PrivateKey, error) {
	// Trim whitespace
	keyData := strings.TrimSpace(data)

	// Try hex decoding first
	keyData = strings.TrimPrefix(keyData, "0x")

	keyBytes, err := hex.DecodeString(keyData)
	if err != nil {
		// If hex decoding fails, try using the raw bytes
		keyBytes = []byte(data)
	}

	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing signing key: %w", err)
	}

	return key, nil
}

// LoadSigningKeyFromFile loads a signing key from a file
// The file can contain either hex-encoded or raw bytes
func LoadSigningKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading signing key file: %w", err)
	}

	return LoadSigningKey(string(data))
}

// LoadSigningKeyFromKeystore loads a signing key from an encrypted keystore file
func LoadSigningKeyFromKeystore(keystorePath, password string) (*ecdsa.PrivateKey, error) {
	keystoreJSON, err := os.ReadFile(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("reading signing keystore file: %w", err)
	}

	key, err := keystore.DecryptKey(keystoreJSON, password)
	if err != nil {
		return nil, fmt.Errorf("decrypting signing keystore: %w", err)
	}

	return key.PrivateKey, nil
}
