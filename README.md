# Stagetimer License Package

## Install

```sh
npm i @stagetimerio/license
```

## Create key pair

See: https://github.com/auth0/node-jsonwebtoken/issues/794

```sh
ssh-keygen -t rsa -b 2048 -m PEM -f jwt-2048-RS256.key
openssl rsa -in jwt-2048-RS256.key -pubout -outform PEM -out jwt-2048-RS256.key.pub
```
