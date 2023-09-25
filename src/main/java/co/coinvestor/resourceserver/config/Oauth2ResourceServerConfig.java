package co.coinvestor.resourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Configuration
public class Oauth2ResourceServerConfig {

    /**
     * resource server config
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .mvcMatchers("/hello").permitAll()  // /hello 경로에 대한 모든 요청을 허용합니다.
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
     * jwt parser
     * @return
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new JwtAuthenticationConverter() {
            @Override
            protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
                List<String> authorities = jwt.getClaimAsStringList("authorities");
                List<String> scopes = jwt.getClaimAsStringList("scope");

                List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

                // authorities에서 권한 추출
                if (authorities != null) {
                    grantedAuthorities.addAll(authorities.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList());
                }

                // scope에서 권한 추출
                if (scopes != null) {
                    grantedAuthorities.addAll(scopes.stream()
                            .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                            .toList());
                }

                return grantedAuthorities;
            }
        };
    }

    /**
     * publicKey를 가져오는 설정
     * @return
     */
    private RSAPublicKey getPublicKey() {
        try {
            String publicKeyEndpoint = "http://localhost/oauth/token_key";
            String clientId = "resourceserver";
            String clientSecret = "resourceserversecret";
            RestTemplate restTemplate = new RestTemplate();

            // Basic Auth headers를 설정하기 위해 HttpHeaders 생성
            HttpHeaders headers = new HttpHeaders();
            String auth = clientId + ":" + clientSecret;
            byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(StandardCharsets.US_ASCII));
            String authHeader = "Basic " + new String(encodedAuth);
            headers.set(HttpHeaders.AUTHORIZATION, authHeader);
            HttpEntity<String> entity = new HttpEntity<>(null, headers);

            ResponseEntity<Map> responseEntity = restTemplate.exchange(publicKeyEndpoint, HttpMethod.GET, entity, Map.class);
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
     * Bearer Token bringer
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
