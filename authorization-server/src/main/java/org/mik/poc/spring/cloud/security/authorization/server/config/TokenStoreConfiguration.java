package org.mik.poc.spring.cloud.security.authorization.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
public class TokenStoreConfiguration
{

    @Bean
    public TokenStore tokenStore()
    {
        return new InMemoryTokenStore();
        //there is other options like a jdbc tokenstore
    }

}
