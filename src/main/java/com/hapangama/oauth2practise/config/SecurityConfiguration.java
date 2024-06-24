package com.hapangama.oauth2practise.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http

                .authorizeHttpRequests((authz) -> authz
                        .anyRequest().authenticated()

                )

                .oauth2Login(
                        (oauth) -> oauth
                        .tokenEndpoint((uep) -> uep
                                .accessTokenResponseClient(new RestOAuth2AccessTokenResponseClient(restOperations()))
                        )
                        .userInfoEndpoint((uie) -> uie
                                .userService(new RestOAuth2UserService(restOperations())
                        )
                )

                );

        return http.build();
    }

    @Bean
    public RestOperations restOperations() {
        return new RestTemplate();
    }
    public static final String DISCORD_BOT_USER_AGENT = "DiscordBot (https://github.com/fourscouts/blog/tree/master/oauth2-discord)";
}



