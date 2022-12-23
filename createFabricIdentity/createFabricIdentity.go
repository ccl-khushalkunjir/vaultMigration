package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"

	vault "github.com/hashicorp/vault/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"gopkg.in/alecthomas/kingpin.v2"
)

// env vars
var (
	VAULT_URL         = os.Getenv("VAULT_URL")
	VAULT_ADMIN_TOKEN = os.Getenv("VAULT_ADMIN_TOKEN") //hvs.voGdhMA3qYQQH9369d8kZ5oN
)

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
	var userName string = os.Args[2]
	var MSPID string = os.Args[3]
	fabricUserIdentity, err := registerUserInVault(vaultclient, orgName, userName, MSPID)
	// wallet.Put("vaultUser", fabricUserIdentity)
	fmt.Println(fabricUserIdentity)

}

func registerUserInVault(vaultclient *vault.Client, org, commonName, MSPID string) (*FabricIdentity, error) {
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
		MSPID:       MSPID, //changed from org to Org1MSP
		Type:        "X.509",
	}
	_, err = vaultclient.Logical().Write(fmt.Sprintf("fabricIdentity/%s", commonName), map[string]interface{}{
		"credentials": fabricCredentials,
		"mspId":       MSPID, //changed from org to Org1MSP
		"type":        "X.509",
	})
	identity := gateway.NewX509Identity(MSPID, cryptoMaterial.Data["certificate"].(string), cryptoMaterial.Data["private_key"].(string))
	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}
	wallet.Put(commonName, identity)

	return &fabricIdentity, err
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
