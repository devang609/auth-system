package com.devang.auth_server.services;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.stereotype.Service;

import com.devang.auth_server.repos.UserRepository;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class TokenService {

    @Autowired
    UserRepository userRepo;

    private JwtClaimsSet claimFactory(String username) {
        String jti = UUID.randomUUID().toString();

        String role = userRepo.findByUsername(username).getRole().getName();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(username)
                .issuer("https://localhost:9090")
                .audience(List.of("https://localhost:8080"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("scope", role)
                .id(jti)
                .build();

        return claims;
    }

    public static RSAPrivateKey keyLoader(Resource resource) throws Exception {

        String pem = new String(
                resource.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);

        pem = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(pem);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private String tokenFactory(String username) throws Exception {

        JWTClaimsSet claims = claimFactory(username);

        RSAPrivateKey privateKey = keyLoader(new ClassPathResource("private.pem"));

        JWSSigner signer = new RSASSASigner(privateKey);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID("auth-rsa-2025-01") // stable kid
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);

        signedJWT.sign(signer);

        return signedJWT.serialize();
    }
}
