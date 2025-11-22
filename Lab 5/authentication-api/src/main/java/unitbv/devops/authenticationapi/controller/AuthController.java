package unitbv.devops.authenticationapi.controller;

import unitbv.devops.authenticationapi.dto.auth.LoginRequest;
import unitbv.devops.authenticationapi.dto.auth.LoginResponse;
import unitbv.devops.authenticationapi.dto.auth.TokenRefreshRequest;
import unitbv.devops.authenticationapi.user.entity.Token;
import unitbv.devops.authenticationapi.user.entity.User;
import unitbv.devops.authenticationapi.user.repository.TokenRepository;
import unitbv.devops.authenticationapi.user.repository.UserRepository;
import unitbv.devops.authenticationapi.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // Find user by username or email
        User user = userRepository.findByUsername(loginRequest.usernameOrEmail())
                .or(() -> userRepository.findByEmail(loginRequest.usernameOrEmail()))
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate password (User entity uses passwordHash field)
        if (!passwordEncoder.matches(loginRequest.password(), user.getPasswordHash())) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        // Extract roles from user (roles is a Set<Role> enum)
        List<String> roles = user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toList());

        // Generate tokens
        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), roles);
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        // Save tokens to database
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setUser(user);
        token.setBlacklisted(false);
        tokenRepository.save(token);

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }

    @PostMapping("/token")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
        // Find the token pair
        Token token = tokenRepository.findByAccessTokenAndRefreshToken(
                        request.getAccessToken(), request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Invalid token pair"));

        // Blacklist the old token pair
        token.setBlacklisted(true);
        tokenRepository.save(token);

        // Validate refresh token
        String username = jwtUtil.extractUsername(request.getRefreshToken());
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!jwtUtil.validateToken(request.getRefreshToken(), username)) {
            return ResponseEntity.status(401).body("Invalid refresh token");
        }

        // Generate new token pair
        List<String> roles = user.getRoles().stream()
                .map(Enum::name)
                .collect(Collectors.toList());

        String newAccessToken = jwtUtil.generateAccessToken(username, roles);
        String newRefreshToken = jwtUtil.generateRefreshToken(username);

        // Save new tokens to database
        Token newToken = new Token();
        newToken.setAccessToken(newAccessToken);
        newToken.setRefreshToken(newRefreshToken);
        newToken.setUser(user);
        newToken.setBlacklisted(false);
        tokenRepository.save(newToken);

        return ResponseEntity.ok(new LoginResponse(newAccessToken, newRefreshToken));
    }
}