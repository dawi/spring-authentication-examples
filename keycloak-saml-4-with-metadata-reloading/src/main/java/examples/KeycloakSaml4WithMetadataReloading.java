package examples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class KeycloakSaml4WithMetadataReloading {

    public static void main(String[] args) {
        SpringApplication.run(KeycloakSaml4WithMetadataReloading.class, args);
    }
}
