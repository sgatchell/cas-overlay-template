package org.plos.cas.config;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.plos.cas.web.flow.EnvironmentAction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration("PlosConfig")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class PlosConfig {

  @Autowired
  private CasConfigurationProperties casProperties;

  @Bean
  public EnvironmentAction environmentAction() {
    return new EnvironmentAction();
  }
}
