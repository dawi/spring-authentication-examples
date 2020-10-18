package examples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class KeycloakSaml5WithBootifulMetadataReloading {

    public static void main(String[] args) {
        SpringApplication.run(KeycloakSaml5WithBootifulMetadataReloading.class, args);
    }
}
