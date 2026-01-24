# List Available Slots
& "C:\SoftHSM2\bin\softhsm2-util.exe" --show-slots  
# Create a New Token
```
& "C:\SoftHSM2\bin\softhsm2-util.exe" `  
  --init-token --slot 0 `  
  --label "TestToken" `  
  --so-pin 0000 `  
  --pin 1234
```
# Generate a protected key inside the token  
```
& "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" `  
  --module "C:\SoftHSM2\lib\softhsm2-x64.dll" `  
  --login --pin 1234 `  
  --keypairgen --key-type rsa:2048 `  
  --id 01 --label "auth-key"  
```
# List Objects in a Token 
```
& "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" `
  --module "C:\SoftHSM2\lib\softhsm2-x64.dll" `
  --login --pin 1234 -O
  ```
# Create certificate based on private key
```
openssl req -new -x509 -days 365 -sha256 `
  -key "pkcs11:token=TestToken;object=auth-key;type=private" `
  -subj "/CN=rfrisch" `
  -out rfrisch-cert.pem
  ```
# import the cert in the token
    ```
  & "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" `
  --module "C:\SoftHSM2\lib\softhsm2-x64.dll" `
  --login --pin 1234 `
  --write-object .\rfrisch-cert.pem `
  --type cert `
  --id 01 `
  --label "rfrisch cert"
    ```
# Vérifier si lien avec dll pkcs11
openssl storeutl -text "pkcs11:token=TestToken"