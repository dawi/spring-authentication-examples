# Spring Authentication Examples

I started this playground project because I had a few problems configuring SAML2 with Keycloak and [Spring Security SAML 2.0](https://docs.spring.io/spring-security/site/docs/5.4.1/reference/html5/#servlet-saml2).
Thomas Darimonts article [How to secure a Spring Boot app with SAML and Keycloak](https://blog.codecentric.de/en/2019/03/secure-spring-boot-app-saml-keycloak/) and the corresponding [spring-boot-security-saml-sample](https://github.com/thomasdarimont/spring-boot-security-saml-sample/tree/poc/keycloak-saml-idp) helped me a lot to get started. 

## Keycloak SAML authentication examples

* [keycloak-saml-1-legacy](keycloak-saml-1-legacy) (this basically is Thomas Darimonts [spring-boot-security-saml-sample](https://github.com/thomasdarimont/spring-boot-security-saml-sample/tree/poc/keycloak-saml-idp))
* [keycloak-saml-2-only-application-properties](keycloak-saml-2-only-application-properties)
* [keycloak-saml-3-only-java-config](keycloak-saml-3-only-java-config)
* [keycloak-saml-4-with-metadata-reloading](keycloak-saml-4-with-metadata-reloading)
* [keycloak-saml-5-with-bootiful-metadata-reloading](keycloak-saml-5-with-bootiful-metadata-reloading)
* [keycloak-saml-6-with-metadata-caching-and-reloading](keycloak-saml-6-with-metadata-caching-and-reloading)

## Keycloak realm configuration (required by this examples)

* Realm export ([realm-export.json](keycloak/realm-export.json))
* Signing Key ([X509 Certificate](keycloak/certificates/signing.crt), [X509 Private Key](keycloak/certificates/signing.key), [JKS Keystore](keycloak/keystores/signing-key-keystore.jks), [P12 Keystore](keycloak/keystores/signing-key-keystore.p12))
* Encryption Key ([X509 Certificate](keycloak/certificates/encryption.crt), [X509 Private Key](keycloak/certificates/encryption.key), [JKS Keystore](keycloak/keystores/encryption-key-keystore.jks), [P12 Keystore](keycloak/keystores/encryption-key-keystore.p12))

# Documentation

## Keycloak Installation and Configuration

* docker-compose up
* Import realm
* Create user in `DemoRealm`
* Start example
* Login

## Metadata URLs

### IDP Metadata URL
* http://localhost:8081/auth/realms/DemoRealm/protocol/saml/descriptor `IDP`

### SP Metadata URLs

They are configurable, but currently the `registrationId` needs to be part of the URL.  
 
* http://localhost:8080/saml/metadata `Default if legacy library is used (example 1)`
* http://localhost:8080/saml2/service-provider-metadata/demo-saml-client `DEFAULT (example 3)`  
* http://localhost:8080/saml/metadata `HACK (example 4)`
* http://localhost:8080/saml/metadata/demo-saml-client `ADJUSTED (example 5 and 6)`

## About Keycloak Configuration

In a Keycloak SAML client configuration it is possible to manage `signing` and `encryption` keys.  
*Keycloak does not need to know the signing an encryption private keys.*  
It is possible to `Generate new keys`, `Import` and `Export` keys.  
If you generate new keys, keycloak stores both, the public and the private key, so that you can later export it as either JKS or PKCS12 keystore.    
If you import existing keystores, only the public key will be stored.

### Signing Key

This key has to be configured if `Client Signature Required` is `true`.  
The client uses the private key to sign a SAML-Request and Keycloak uses the public key to verify it.  
**Keycloak does not need to know the private key.**

### Encryption Key

This key has to be configured if `Encrypt Assertions` is `true`.  
Keycloak encrypts the SAML-Assertion with the clients public key, and the client uses its private key to decrypt the SAML-Assertion.  
**Keycloak does not need to know the private key.**
