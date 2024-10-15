# Python wrapper for Interactive Brokers Web API [NOT COMPLETE]

## Official documentation

https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#introduction

## Prerequisites

Interactive Brokers Web API requires obtaining the following keys:

```
"consumer_key": "<CONSUMER KEY>",
"dhparam": "./data/dhparam.pem",
"encryption": "./data/private_encryption.pem",
"signature": "./data/private_signature.pem",
"access_token": "<GENERATED ACCESS TOKEN>",
"access_token_secret": "<GENERATED ACCESS TOKEN SECRET>"
```

## Steps to generate `access_token` and `access_token_secret`

1. Login to https://ndcdyn.interactivebrokers.com/sso/Login?action=OAUTH with your account
2. Enter Consumer Key
3. Generate Public Signing Key

```
openssl genrsa -out private_signature.pem 2048
openssl rsa -in private_signature.pem -outform PEM -pubout -out public_signature.pem
```

4. Generate Public Encryption Key

```
openssl genrsa -out private_encryption.pem 2048
openssl rsa -in private_encryption.pem -outform PEM -pubout -out public_encryption.pem
```

5. Generate Diffie-Hellman Parameters

```
openssl dhparam -outform PEM -out dhparam.pem 2048
```

6. Upload keys and dhparam.pem files to generate access token and secret
![image](https://github.com/user-attachments/assets/05b862f2-cbc8-4c56-9b53-17a315363da4)

7. Generate token

8. Test requests could be found in `/tests`
