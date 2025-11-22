package unitbv.devops.authenticationapi.dto.auth;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank String usernameOrEmail,
        @NotBlank String password
) {
    @Override
    public String usernameOrEmail() {
        return usernameOrEmail;
    }

    @Override
    public String password() {
        return password;
    }
}
