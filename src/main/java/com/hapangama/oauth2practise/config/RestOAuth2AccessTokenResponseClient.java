package com.hapangama.oauth2practise.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RestOAuth2AccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    private RestOperations restOperations;
    public static final String DISCORD_BOT_USER_AGENT = "DiscordBot (https://github.com/fourscouts/blog/tree/master/oauth2-discord)";

    public RestOAuth2AccessTokenResponseClient(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

        String tokenUri = clientRegistration.getProviderDetails().getTokenUri();

        MultiValueMap<String, String> tokenRequest = new LinkedMultiValueMap<String, String>();
        tokenRequest.add("client_id", clientRegistration.getClientId());
        tokenRequest.add("client_secret", clientRegistration.getClientSecret());
        tokenRequest.add("grant_type", clientRegistration.getAuthorizationGrantType().getValue());
        tokenRequest.add("code", authorizationGrantRequest.getAuthorizationExchange().getAuthorizationResponse().getCode());
        tokenRequest.add("redirect_uri", authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getRedirectUri());
        tokenRequest.add("scope", String.join(" ", authorizationGrantRequest.getClientRegistration().getScopes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add(HttpHeaders.USER_AGENT, DISCORD_BOT_USER_AGENT);

        ResponseEntity<AccessResponse> response =
                restOperations.exchange(tokenUri, HttpMethod.POST, new HttpEntity<>(tokenRequest, headers), AccessResponse.class);

        AccessResponse accessResponse = response.getBody();

        Set<String> scopes = accessResponse.getScopes().isEmpty() ?
                authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes() : accessResponse.getScopes();

        return OAuth2AccessTokenResponse.withToken(accessResponse.getAccessToken())
                .tokenType(accessResponse.getTokenType())
                .expiresIn(accessResponse.getExpiresIn())
                .scopes(scopes)
                .build();
    }

    static class AccessResponse {
        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("token_type")
        private String tokenType;

        @JsonProperty("expires_in")
        private int expiresIn;

        @JsonProperty("refresh_token")
        private String refreshToken;

        private String scope;

        public AccessResponse() {}

        AccessResponse(String accessToken, String tokenType, int expiresIn, String refreshToken, String scope) {
            this.accessToken = accessToken;
            this.tokenType = tokenType;
            this.expiresIn = expiresIn;
            this.refreshToken = refreshToken;
            this.scope = scope;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public OAuth2AccessToken.TokenType getTokenType() {
            return OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(tokenType) ? OAuth2AccessToken.TokenType.BEARER : null;
        }

        public int getExpiresIn() {
            return expiresIn;
        }

        public Set<String> getScopes() {
            return StringUtils.isEmpty(scope) ? Collections.emptySet() : Stream.of(scope.split("\\s+")).collect(Collectors.toSet());
        }
    }
}
