package org.plos.authentication.support.password;

// import org.plos.namedentity.service.PasswordDigestService;
import org.springframework.security.crypto.password.AbstractPasswordEncoder;

public class NedPasswordEncoder extends AbstractPasswordEncoder {
    @Override
    protected byte[] encode(CharSequence rawPassword, byte[] salt) {
      System.out.println("$$$$$$$$$$$$$$$$$$$$ in ned password encoder, raw password = " + rawPassword);
      return "foo".getBytes();
    }

    @Override
      public boolean matches(CharSequence rawPassword, String encodedPassword) {
        System.out.println("%%%%%%%%%%%%% matching " + rawPassword.toString() + " and " + encodedPassword + "but as a fake always returning the password for sgatchell@plos.org");
        return "6b83e651ae5446d6916d8cc8200751398e81302d71ad008260b97af764551fe61b27b8ac3c34cfd46f98af2828bf43dbe653074cf250d563f309e75ae8423f70".equals(encodedPassword);
    }
}
