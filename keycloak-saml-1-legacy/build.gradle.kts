plugins {
    id("org.springframework.boot") version "2.3.4.RELEASE"
    id("io.spring.dependency-management") version "1.0.10.RELEASE"
    `java`
}

version = "unspecified"

repositories {
    mavenCentral()
    maven("https://build.shibboleth.net/nexus/content/repositories/releases")
}

dependencies {

    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-tomcat")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("nz.net.ultraq.thymeleaf:thymeleaf-layout-dialect")

    implementation("org.springframework.security.extensions:spring-security-saml2-core:1.0.10.RELEASE")
}
