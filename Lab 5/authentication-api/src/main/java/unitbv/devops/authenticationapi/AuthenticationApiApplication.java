package unitbv.devops.authenticationapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories("unitbv.devops.authenticationapi.user.repository")
@EntityScan("unitbv.devops.authenticationapi.user.entity")
public class AuthenticationApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationApiApplication.class, args);
    }

}
