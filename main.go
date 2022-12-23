package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"gopkg.in/alecthomas/kingpin.v2"
)

// env vars
var (
	VAULT_URL         = os.Getenv("VAULT_URL")
	VAULT_ADMIN_TOKEN = os.Getenv("VAULT_ADMIN_TOKEN") //hvs.voGdhMA3qYQQH9369d8kZ5oN
)

// command line flags
var (
	app           = kingpin.New("fabric-vault-plugin-util", "Utility for Initialzing Vault for Hyperledger Fabric")
	enable        = app.Command("enable", "Enables the PKI/Transit engine")
	orgName       = enable.Flag("org_name", "Organization name").Required().String()
	identitygen   = app.Command("identitygen", "Creates the identities from the passed file")
	genConfigFile = identitygen.Flag("config", "The configuration template to use").File()
	version       = app.Command("version", "Show version information")
)

type NodeSpec struct {
	isAdmin            bool
	Hostname           string   `yaml:"Hostname"`
	CommonName         string   `yaml:"CommonName"`
	Country            string   `yaml:"Country"`
	Province           string   `yaml:"Province"`
	Locality           string   `yaml:"Locality"`
	OrganizationalUnit string   `yaml:"OrganizationalUnit"`
	StreetAddress      string   `yaml:"StreetAddress"`
	PostalCode         string   `yaml:"PostalCode"`
	SANS               []string `yaml:"SANS"`
}
type UsersSpec struct {
	Name string `yaml:"name"`
}
type Config struct {
	OrdererOrgs []OrgSpec `yaml:"OrdererOrgs"`
	PeerOrgs    []OrgSpec `yaml:"PeerOrgs"`
}

type OrgSpec struct {
	Name          string      `yaml:"Name"`
	Domain        string      `yaml:"Domain"`
	EnableNodeOUs bool        `yaml:"EnableNodeOUs"`
	Peers         []NodeSpec  `yaml:"Peers"`
	Orderers      []NodeSpec  `yaml:"Orderers"`
	Users         []UsersSpec `yaml:"Users"`
	Admins        []UsersSpec `yaml:"Admins"`
}

type FabricCredentials struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey"`
}

type FabricIdentity struct {
	Credentials FabricCredentials `json:"credentials"`
	MSPID       string            `json:"mspId"`
	Type        string            `json:"type"`
}

func main() {
	kingpin.Version("0.0.1")

	if VAULT_URL == "" {
		log.Panicln("Please setup the Vault Address")
	}

	if VAULT_ADMIN_TOKEN == "" {
		log.Panicln("Please setup the Vault Token")
	}

	// connect to vault
	vaultclient, err := initVault(VAULT_URL, VAULT_ADMIN_TOKEN)
	if err != nil {
		log.Panicln(err)
	}
	var orgName string = os.Args[1]
	var peerPrivateKeyFileName string = os.Args[2]
	var adminPrivateKeyFileName string = os.Args[3]
	var userPrivateKeyFileName string = os.Args[4]

	err = createOrgIdentityCA(vaultclient, orgName)
	if err != nil {
		fmt.Println("error when createOrgIdentityCA", err)
	}
	// Enable transit
	err = enableTransitInVault(vaultclient, orgName)
	if err != nil {
		fmt.Println("error when enableTransitInVault", err)
	}

	peerKeyStore := filepath.Join(
		"peerOrganizations",
		orgName+".example.com",
		"peers",
		"peer0."+orgName+".example.com",
		"msp",
		"keystore",
		peerPrivateKeyFileName,
	)
	adminKeyStore := filepath.Join(
		"peerOrganizations",
		orgName+".example.com",
		"users",
		"Admin@"+orgName+".example.com",
		"msp",
		"keystore",
		adminPrivateKeyFileName,
	)
	userKeyStore := filepath.Join(
		"peerOrganizations",
		orgName+".example.com",
		"users",
		"User1@"+orgName+".example.com",
		"msp",
		"keystore",
		userPrivateKeyFileName,
	)
	peerData, err := ioutil.ReadFile(filepath.Clean(peerKeyStore))
	if err != nil {
		log.Panicf("failed reading data from file peerData: %s", err)
	}
	fmt.Println("peerData")
	err = importPrivateKeys(vaultclient, peerData, orgName, "peer0"+orgName+".example.com")
	if err != nil {
		log.Panicf("failed importPrivateKeys peerData: %s", err)
	}

	adminData, err := ioutil.ReadFile(filepath.Clean(adminKeyStore))
	if err != nil {
		log.Panicf("failed reading data from file adminData: %s", err)
	}
	fmt.Println("adminData")
	err = importPrivateKeys(vaultclient, adminData, orgName, "admin-"+orgName+".example.com")
	if err != nil {
		log.Panicf("failed importPrivateKeys adminData: %s", err)
	}
	userData, err := ioutil.ReadFile(filepath.Clean(userKeyStore))
	if err != nil {
		log.Panicf("failed reading data from file userData: %s", err)
	}
	fmt.Println("userData", string(userData))
	err = importPrivateKeys(vaultclient, userData, orgName, "user-"+orgName+".example.com")
	if err != nil {
		log.Panicf("failed importPrivateKeys userData: %s", err)
	}

	pemData, err := ioutil.ReadFile("./bundle.pem")

	if err != nil {
		log.Fatalf("Failed to reading bundle: %v", err)
	}
	submit := submitPemBundleForICA(vaultclient, orgName, string(pemData))
	fmt.Printf("%s", submit)

}
func submitPemBundleForICA(vaultclient *vault.Client, org, pem_bundle string) error {
	pemBundleConfig := map[string]interface{}{
		"pem_bundle": pem_bundle,
	}
	_, err := vaultclient.Logical().Write(fmt.Sprintf("/%s_CA/config/ca", org), pemBundleConfig)
	return err
}

func registerUserInVault(vaultclient *vault.Client, org, commonName string) (*FabricIdentity, error) {
	adminRoleConfig := map[string]interface{}{
		"server_flag":                        false,
		"client_flag":                        false,
		"key_type":                           "ec",
		"key_bits":                           256,
		"key_usage":                          []string{"DigitalSignature"},
		"max_ttl":                            "876000h",
		"ttl":                                "876000h",
		"generate_lease":                     true,
		"allow_any_name":                     true,
		"ou":                                 "client",
		"organization":                       org,
		"basic_constraints_valid_for_non_ca": true,
	}
	_, err := vaultclient.Logical().Write(fmt.Sprintf("%s_CA/roles/%s", org, commonName), adminRoleConfig)
	certConfig := map[string]interface{}{
		"common_name": commonName,
		"ttl":         157680000,
	}
	cryptoMaterial, err := vaultclient.Logical().Write(fmt.Sprintf("%s_CA/issue/%s", org, commonName), certConfig)
	if err != nil {
		return nil, err
	}
	// certificate, err := ioutil.ReadFile("/home/khushal/workspace/test-vault/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/cert.pem")
	// fmt.Printf("%s", certificate)
	fabricCredentials := FabricCredentials{
		Certificate: cryptoMaterial.Data["certificate"].(string),
		PrivateKey:  cryptoMaterial.Data["private_key"].(string),
	}
	fabricIdentity := FabricIdentity{
		Credentials: fabricCredentials,
		MSPID:       "Org1MSP", //changed from org to Org1MSP
		Type:        "X.509",
	}
	_, err = vaultclient.Logical().Write(fmt.Sprintf("fabricIdentity/%s", commonName), map[string]interface{}{
		"credentials": fabricCredentials,
		"mspId":       "Org1MSP", //changed from org to Org1MSP
		"type":        "X.509",
	})
	identity := gateway.NewX509Identity("Org1MSP", cryptoMaterial.Data["certificate"].(string), cryptoMaterial.Data["private_key"].(string))
	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}
	wallet.Put("testvaultuser1", identity)

	return &fabricIdentity, err
}

func importPrivateKeys(vaultclient *vault.Client, data []byte, orgName, commonName string) error {

	privatekey, err := getPrivateKeyData([]byte(data))
	if err != nil {
		fmt.Println(err)
	}
	transitPath := fmt.Sprintf("%s_Transit/restore/%s", orgName, commonName)
	transitPayload := make(map[string]interface{})
	transitPayload["backup"] = privatekey
	transitPayload["force"] = 1
	_, err = vaultclient.Logical().Write(transitPath, transitPayload)
	if err != nil {
		fmt.Println(err)
	}
	return nil
}

func createOrgIdentityCA(vaultclient *vault.Client, org string) error {
	orgPKIConfig := map[string]interface{}{
		"type": "pki",
		"config": map[string]string{
			"max_lease_ttl":     "87600h",
			"default_lease_ttl": "87600h",
		},
		"seal_wrap": true,
	}
	_, err := vaultclient.Logical().Write(fmt.Sprintf("/sys/mounts/%s_CA", org), orgPKIConfig)
	return err
}

func createPeerRoleInPKI(vaultclient *vault.Client, org string, peerName string) error {
	peerRoleConfig := map[string]interface{}{
		"server_flag":                        false,
		"client_flag":                        false,
		"key_type":                           "ec",
		"key_bits":                           256,
		"key_usage":                          []string{"DigitalSignature"},
		"max_ttl":                            "876000h",
		"generate_lease":                     true,
		"allow_any_name":                     true,
		"ou":                                 "peer",
		"organization":                       org,
		"allowed_domains":                    fmt.Sprintf("%s.%s.svc.cluster.local", peerName, org),
		"allow_subdomains":                   true,
		"basic_constraints_valid_for_non_ca": true,
	}
	_, err := vaultclient.Logical().Write(fmt.Sprintf("%s_CA/roles/%s", org, peerName), peerRoleConfig)
	return err
}
func enableTransitInVault(vaultclient *vault.Client, orgName string) error {
	orgPKIConfig := map[string]interface{}{
		"type": "transit",
		"config": map[string]string{
			"max_lease_ttl":     "87600h",
			"default_lease_ttl": "87600h",
		},
		"seal_wrap": true,
	}
	_, err := vaultclient.Logical().Write(fmt.Sprintf("/sys/mounts/%s_Transit", orgName), orgPKIConfig)
	return err
}
func createRoleInPKI(vaultclient *vault.Client, orgName, commonName string) error {
	// log.Printf("---- Vault PKI role created for %s", node.CommonName)
	rolePath := fmt.Sprintf("%s_CA/roles/%s", orgName, commonName)
	roleConfig := map[string]interface{}{
		"server_flag":                        false,
		"client_flag":                        false,
		"key_type":                           "ec",
		"key_bits":                           256,
		"key_usage":                          []string{"DigitalSignature"},
		"max_ttl":                            "87600h",
		"generate_lease":                     true,
		"allow_any_name":                     true,
		"ou":                                 "peer",
		"organization":                       orgName,
		"allowed_domains":                    commonName,
		"allow_subdomains":                   true,
		"basic_constraints_valid_for_non_ca": true,
	}

	_, err := vaultclient.Logical().Write(rolePath, roleConfig)
	return err
}
func initVault(address, token string) (*vault.Client, error) {
	config := &vault.Config{
		Address: address,
		HttpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	return client, nil
}

func getPrivateKeyData(privatekeybytes []byte) (string, error) {
	privateKeyData, err := pemToPrivateKey(privatekeybytes, nil)
	if err != nil {
		return "", err
	}

	privateKey := privateKeyData.(*ecdsa.PrivateKey)
	publicKeyPEM, err := publicKeyToPEM(&privateKey.PublicKey, nil)
	if err != nil {
		return "", err
	}

	var escapedpublicKeyPEM string = strings.Replace(string(publicKeyPEM), "\n", `\n`, -1)
	data := getKeyRestoreData(privateKey, escapedpublicKeyPEM)
	base64data := base64.StdEncoding.EncodeToString([]byte(data))
	return base64data, nil
}

func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	// TODO: derive from header the type of the key

	if x509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}

		decrypted, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}

		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := derToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

func derToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("invalid key type. The DER must contain an ecdsa.PrivateKey")
}

func publicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return publicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa public key. It must be different from nil")
		}
		PubASN1, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: PubASN1,
			},
		), nil

	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PublicKey")
	}
}

func publicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	switch k := publicKey.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, errors.New("invalid ecdsa public key. It must be different from nil")
		}
		raw, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}

		block, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PUBLIC KEY",
			raw,
			pwd,
			x509.PEMCipherAES256)

		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(block), nil
	default:
		return nil, errors.New("invalid key type. It must be *ecdsa.PublicKey")
	}
}

func getKeyRestoreData(privateKey *ecdsa.PrivateKey, publickKey string) string {
	data := fmt.Sprintf(`{"policy":{"name":"orderer0","keys":{"1":{"key":null,"hmac_key":"Mhjm25N1JZc85Bd4dBZnAJoziWi8ffkTDqSl2wfm/YI=","time":"2022-08-23T04:16:18.96357229Z","ec_x":%s,"ec_y":%s,"ec_d":%s,"rsa_key":null,"public_key":"%s","convergent_version":0,"creation_time":1661228178}},"derived":false,"kdf":0,"convergent_encryption":false,"exportable":true,"min_decryption_version":1,"min_encryption_version":0,"latest_version":1,"archive_version":1,"archive_min_version":0,"min_available_version":0,"deletion_allowed":false,"convergent_version":0,"type":1,"backup_info":{"time":"2022-08-25T05:55:05.250141245Z","version":1},"restore_info":null,"allow_plaintext_backup":true,"version_template":"","storage_prefix":"","auto_rotate_period":0,"Imported":false,"AllowImportedKeyRotation":false},"archived_keys":{"keys":[{"key":null,"hmac_key":null,"time":"0001-01-01T00:00:00Z","ec_x":null,"ec_y":null,"ec_d":null,"rsa_key":null,"public_key":"","convergent_version":0,"creation_time":0},{"key":null,"hmac_key":"Mhjm25N1JZc85Bd4dBZnAJoziWi8ffkTDqSl2wfm/YI=","time":"2022-08-23T04:16:18.96357229Z","ec_x":%s,"ec_y":%s,"ec_d":%s,"rsa_key":null,"public_key":"%s","convergent_version":0,"creation_time":1661228178}]}}`, privateKey.PublicKey.X.String(), privateKey.PublicKey.Y.String(), privateKey.D.String(), publickKey, privateKey.PublicKey.X.String(), privateKey.PublicKey.Y.String(), privateKey.D.String(), publickKey)
	return data
}

func createFolderStructure(rootDir string, local bool) error {
	var folders []string
	// create admincerts, cacerts, keystore and signcerts folders
	folders = []string{
		filepath.Join(rootDir, "admincerts"),
		filepath.Join(rootDir, "cacerts"),
		filepath.Join(rootDir, "tlscacerts"),
		filepath.Join(rootDir, "intermediatecerts"),
		filepath.Join(rootDir, "tlsintermediatecerts"),
	}

	if local {
		folders = append(folders, filepath.Join(rootDir, "keystore"),
			filepath.Join(rootDir, "signcerts"))
	}

	for _, folder := range folders {
		err := os.MkdirAll(folder, 0755)
		if err != nil {
			return err
		}
	}

	return nil
}

func parseTemplateWithDefault(input, defaultInput string, data interface{}) (string, error) {

	// Use the default if the input is an empty string
	if len(input) == 0 {
		input = defaultInput
	}

	return parseTemplate(input, data)
}

func parseTemplate(input string, data interface{}) (string, error) {

	t, err := template.New("parse").Parse(input)
	if err != nil {
		return "", fmt.Errorf("Error parsing template: %s", err)
	}

	output := new(bytes.Buffer)
	err = t.Execute(output, data)
	if err != nil {
		return "", fmt.Errorf("Error executing template: %s", err)
	}

	return output.String(), nil
}
