package co.coinvestor.resourceserver.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
public class Oauth2ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/hello").permitAll()  // /hello 경로에 대한 모든 요청을 허용합니다.
                .anyRequest().authenticated() // 그 외의 모든 요청은 인증이 필요합니다.
                .and()
                .oauth2ResourceServer().jwt().decoder(jwtDecoder());

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
                .withPublicKey(getPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        return jwtDecoder;
    }

    /**
     * publicKey를 가져오는 설정
     * @return
     */
    private RSAPublicKey getPublicKey() {
        try {
            String publicKeyEndpoint = "http://localhost/oauth/token_key";
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<?> responseEntity = restTemplate.getForEntity(publicKeyEndpoint, Map.class);
            Map<String, String> response = (Map<String, String>) responseEntity.getBody();
            String publicKeyValue = extractPubKey(response.get("value"));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyValue));
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception ex) {
            throw new RuntimeException("키를 불러올 수 없습니다.", ex);
        }
    }

    private String extractPubKey(String publicKeyValue) {
        publicKeyValue = publicKeyValue
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\n", "")
                .trim();
        return publicKeyValue;
    }

    /**
     * Bearer Token의 위치를 특정해서 가져오는 설정
     */
    @Bean
    public BearerTokenResolver customBearerTokenResolver() {
        return new BearerTokenResolver() {
            private DefaultBearerTokenResolver defaultResolver = new DefaultBearerTokenResolver();

            @Override
            public String resolve(HttpServletRequest request) {
                String bearerToken = defaultResolver.resolve(request);
                if (bearerToken != null) {
                    return bearerToken;
                }

                // Cookie에서 토큰을 찾아보는 로직 추가
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                    for (Cookie cookie : cookies) {
                        if ("TOKEN".equals(cookie.getName())) {
                            return cookie.getValue();
                        }
                    }
                }

                return null;
            }
        };
    }


}
