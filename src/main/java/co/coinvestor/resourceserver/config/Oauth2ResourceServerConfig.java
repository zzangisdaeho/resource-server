package co.coinvestor.resourceserver.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class Oauth2ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OpaqueTokenIntrospector introspector) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/hello").permitAll()  // /hello 경로에 대한 모든 요청을 허용합니다.
                .anyRequest().authenticated()
                .and()// 그 외의 모든 요청은 인증이 필요합니다.
                .oauth2ResourceServer().opaqueToken().introspector(introspector);

        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector introspector(OAuth2ResourceServerProperties properties) {
        return new NimbusOpaqueTokenIntrospector(properties.getOpaquetoken().getIntrospectionUri(),
                properties.getOpaquetoken().getClientId(),
                properties.getOpaquetoken().getClientSecret()) {
            @Override
            public OAuth2AuthenticatedPrincipal introspect(String token) {
                OAuth2AuthenticatedPrincipal principal = super.introspect(token);
                List<String> authoritiesFromResponse = (List<String>) principal.getAttributes().get("authorities");
                Collection<GrantedAuthority> authorities = authoritiesFromResponse.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
                return new DefaultOAuth2AuthenticatedPrincipal(principal.getName(), principal.getAttributes(), authorities);
            }
        };
    }

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
