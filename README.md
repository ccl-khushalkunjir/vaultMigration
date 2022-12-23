## Vault migration


Copy the peerOrganization folder into root directory of this repo

## Create and copy bundle of fabric ca certificates 

Go to fabric-ca/org1/msp/

cat ca-cert.pem ./keystore/<>_pk > bundle.pem 

copy this bundle.pem into this root directory of this repo


## Run command for 
    ### enable PKI and tansite
    ### read the private keys and import into vault
    ### Submit pem bundle of fabric ca 

go run main.go <OrgName> <peer private key name> <Admin private key name> <user1 private key name >

    command example:
    go run main.go org1 6e3bc8c376d54509d63a5560c24e7d04124b71c68f8e1ef5322f4512f98ba196_sk c054528de960a162b181513c4f9835f86ed2edaf2bc7b4732292e685ef1a7e08_sk 689a74ebdfbfab02a4d231f6b36784638ff21ae2ca84967fab8e2583ef42a100_sk
## To register and create farbic identity 
cd createFabricIdentity

go run createFabricIdentity.go <orgName> <user to register> <org msp>

    command example 
        go run createFabricIdentity.go org1 testuser2 Org1MSP
