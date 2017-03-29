package com.vaz;

import org.jose4j.lang.JoseException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Config {

    private final String clientId = "de4ccd30-c313-4530-b1e2-1b1d59b498b9";

    private final String secretId = "EIrSDYgeCt2x56+sp4ngBw";

    private final String audience = "https://id.corp.aol.com/identity/oauth2/access_token";

    @Bean
    public OAuth2 getOAuth2() throws JoseException {
        OAuth2 oAuth2 = new OAuth2();
        oAuth2.obtainOAuth2Token(clientId, secretId, audience);
        return oAuth2;
    }
}
