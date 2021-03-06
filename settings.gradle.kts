// plugin management is required to support spring milestone versions
pluginManagement {

    repositories {
        maven { url = uri("https://repo.spring.io/milestone") }
        maven { url = uri("https://repo.spring.io/snapshot") }
        gradlePluginPortal()
    }

    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "org.springframework.boot") {
                useModule("org.springframework.boot:spring-boot-gradle-plugin:${requested.version}")
            }
        }
    }
}

rootProject.name = "spring-authentication-examples"

include("keycloak-saml-1-legacy")
include("keycloak-saml-2-only-application-properties")
include("keycloak-saml-3-only-java-config")
include("keycloak-saml-4-with-metadata-reloading")
include("keycloak-saml-5-with-bootiful-metadata-reloading")
include("keycloak-saml-6-with-metadata-caching-and-reloading")
