package org.plos.cas.config;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.resolvers.PersonDirectoryPrincipalResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.services.persondir.support.NamedStubPersonAttributeDao;
import org.apereo.services.persondir.support.jdbc.SingleRowJdbcPersonAttributeDao;
import org.plos.cas.authenticationHandler.EmailAddressIncorrectException;
import org.plos.cas.authenticationHandler.NotVerifiedException;
import org.plos.cas.authenticationHandler.PasswordIncorrectException;
import org.plos.cas.service.DatabaseService;
import org.plos.cas.service.DatabaseServiceImpl;
import org.plos.namedentity.service.PasswordDigestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.endpoint.mvc.MvcEndpoint;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.mchange.v2.c3p0.ComboPooledDataSource;


import org.apereo.cas.authentication.PrincipalException;
import org.apereo.cas.authentication.adaptive.UnauthorizedAuthenticationException;

import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.exceptions.InvalidLoginLocationException;
import org.apereo.cas.authentication.exceptions.InvalidLoginTimeException;
import org.apereo.cas.services.UnauthorizedServiceForPrincipalException;
import org.apereo.cas.ticket.UnsatisfiedAuthenticationPolicyException;
import org.apereo.cas.web.flow.actions.AuthenticationExceptionHandlerAction;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.webflow.execution.Action;

import java.beans.PropertyVetoException;
import java.util.*;

import org.springframework.core.env.Environment;
import org.plos.cas.authenticationHandler.DatabaseAuthenticationHandler;

import javax.sql.DataSource;


@Configuration("PlosConfig")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class PlosConfig implements AuthenticationEventExecutionPlanConfigurer {

  @Autowired
  private CasConfigurationProperties casProperties;

  @Autowired
  private Environment environment;

  // custom config properties

  @Value("${auth.database.url:jdbc:mysql://localhost:3306/unknownDb}")
  private String dbUrl;

  @Value("${auth.database.driverClass:com.mysql.jdbc.Driver}")
  private String dbDriver;

  @Value("${auth.database.user:unspecifiedUser}")
  private String dbUser;

  @Value("${auth.database.password:unspecifiedPassword}")
  private String dbPassword;

  @Value("${auth.database.batchSize:10}")
  private Integer dbBatchSize;

  @Value("${auth.database.pool.minSize:6}")
  private Integer dbPoolMinSize;

  @Value("${auth.database.pool.maxSize:18}")
  private Integer dbPoolMaxSize;

  @Bean
  public AuthenticationHandler databaseAuthenticationHandler() {
      DatabaseAuthenticationHandler handler = new DatabaseAuthenticationHandler();

      handler.setDatabaseService(databaseService());
      handler.setPasswordDigestService(nedPasswordDigestService());

      return handler;
  }

  @Override
  public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
    plan.registerAuthenticationHandler(databaseAuthenticationHandler());
  }


  @Bean
  public DatabaseService databaseService() {

    DatabaseServiceImpl service = new DatabaseServiceImpl();

    service.setDataSource(nedDataSourceBean());
    service.setPasswordDigestService(nedPasswordDigestService());

    return service;
  }

  @Bean
  public PasswordDigestService nedPasswordDigestService() {
    return new PasswordDigestService();
  }

  @Bean
  public DataSource nedDataSourceBean() {
    ComboPooledDataSource s = new com.mchange.v2.c3p0.ComboPooledDataSource();

    s.setJdbcUrl(dbUrl);
    s.setUser(dbUser);
    s.setPassword(dbPassword);

    try {
        s.setDriverClass(dbDriver);
    } catch (PropertyVetoException e) {
        System.err.println("Error setting db driver: " + e.getMessage());
//        TODO: something reasonable?  Won't compile unless we catch this exception
    }

    return s;
  }

  @ConditionalOnMissingBean(name = "authenticationExceptionHandler")
  @Bean
  public Action authenticationExceptionHandler() {
    return new AuthenticationExceptionHandlerAction(handledAuthenticationExceptions());
  }

  @RefreshScope
  @Bean
  public Set<Class<? extends Exception>> handledAuthenticationExceptions() {
    /*
     * Order is important here; We want the account policy exceptions to be handled
     * first before moving onto more generic errors. In the event that multiple handlers
     * are defined, where one failed due to account policy restriction and one fails
     * due to a bad password, we want the error associated with the account policy
     * to be processed first, rather than presenting a more generic error associated
     */
    final Set<Class<? extends Exception>> errors = new LinkedHashSet<>();
    errors.add(javax.security.auth.login.AccountLockedException.class);
    errors.add(javax.security.auth.login.CredentialExpiredException.class);
    errors.add(javax.security.auth.login.AccountExpiredException.class);
    errors.add(AccountDisabledException.class);
    errors.add(InvalidLoginLocationException.class);
    errors.add(AccountPasswordMustChangeException.class);
    errors.add(InvalidLoginTimeException.class);

    errors.add(javax.security.auth.login.AccountNotFoundException.class);
    errors.add(javax.security.auth.login.FailedLoginException.class);
    errors.add(UnauthorizedServiceForPrincipalException.class);
    errors.add(PrincipalException.class);
    errors.add(UnsatisfiedAuthenticationPolicyException.class);
    errors.add(UnauthorizedAuthenticationException.class);

    // PLOS custom errors
    errors.add(PasswordIncorrectException.class);
    errors.add(NotVerifiedException.class);
    errors.add(EmailAddressIncorrectException.class);

    errors.addAll(casProperties.getAuthn().getExceptions().getExceptions());

    return errors;
  }
}

//  @Bean
//  public NamedStubPersonAttributeDao attributeRepository() {
//    return new NamedStubPersonAttributeDao(attrRepoBackingMap());
//  }
//
//  @Bean
//  public Map<String, String> attrRepoBackingMap() {
//
//    return new HashMap<String, String>() {{
//      put("uid", "uid");
//      put("eduPersonAffiliation","eduPersonAffiliation");
//      put("groupMembership","groupMembership");
////      put("memberOf", new ArrayList<String>() {{
////        add("faculty");
////        add("staff");
////        add("org");
////      }}
////      );
//    }};
//  }


  // Aperta auth works without these beans. Kill if not needed.
  // @Bean(name = {"usernamePasswordPrincipalResolver", "primaryPrincipalResolver"})
  // public PersonDirectoryPrincipalResolver primaryPrincipalResolver() {
  //   return new PersonDirectoryPrincipalResolver(personAttributeDao(), principalFactory(),true,  "username");
  // }


  // @Bean(name = {"defaultPrincipalFactory", "principalFactory"})
  // public PrincipalFactory principalFactory() {
  //   return new DefaultPrincipalFactory();
  // }

  // @Bean
  // public SingleRowJdbcPersonAttributeDao personAttributeDao() {
  //   SingleRowJdbcPersonAttributeDao dao = new SingleRowJdbcPersonAttributeDao(nedDataSourceBean(), "\"\n" +
  //       "SELECT e.emailAddress, i.firstName, i.middleName, i.lastName, i.displayName, a.authId, a.nedId,\n" +
  //       "    CONCAT('[',\n" +
  //       "      IFNULL(GROUP_CONCAT(\n" +
  //       "        DISTINCT\n" +
  //       "        CONCAT('{&quot;applicationtype&quot;:&quot;',gt1.shortDescription,'&quot;,&quot;type&quot;:&quot;',gt2.shortDescription,'&quot;}')\n" +
  //       "        ORDER BY gt1.shortDescription\n" +
  //       "        SEPARATOR ','\n" +
  //       "      ),''),\n" +
  //       "    ']') groups\n" +
  //       "  FROM authCas a\n" +
  //       "  JOIN emails e ON a.emailId = e.id AND a.nedId = e.nedId\n" +
  //       "  JOIN individualProfiles i ON a.nedId = i.nedId\n" +
  //       "  LEFT JOIN groups g ON a.nedId = g.nedId\n" +
  //       "  LEFT JOIN globalTypes gt1 ON g.applicationTypeId = gt1.id\n" +
  //       "  LEFT JOIN globalTypes gt2 ON g.typeId = gt2.id\n" +
  //       "  WHERE {0}\"");

  //   dao.setQueryAttributeMapping(new HashMap<String, String>() {{
  //       put("username", "authId");
  //   }});

  //   dao.setResultAttributeMapping(new HashMap<String, String>() {{
  //       put("authId","authId");
  //       put("displayName","displayName");
  //       put("emailAddress","emailAddress");
  //       put("firstName","firstName");
  //       put("groups","groups");
  //       put("lastName","lastName");
  //       put("middleName","middleName");
  //       put("nedId","nedId");
  //   }});

  //   return dao;
  // }
