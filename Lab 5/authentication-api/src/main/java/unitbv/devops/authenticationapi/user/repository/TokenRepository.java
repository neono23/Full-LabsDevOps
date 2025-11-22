package unitbv.devops.authenticationapi.user.repository;

import unitbv.devops.authenticationapi.user.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByAccessToken(String accessToken);
    Optional<Token> findByRefreshToken(String refreshToken);
    Optional<Token> findByAccessTokenAndRefreshToken(String accessToken, String refreshToken);
}