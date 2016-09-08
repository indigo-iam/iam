package it.infn.mw.iam.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service("iamUserDetailsService")
public class IamUserDetailsService implements UserDetailsService {

  @Autowired
  private IamAccountRepository repo;

  List<GrantedAuthority> convertAuthorities(final IamAccount a) {

    List<GrantedAuthority> authorities = new ArrayList<>();
    for (IamAuthority auth : a.getAuthorities()) {
      authorities.add(new SimpleGrantedAuthority(auth.getAuthority()));
    }
    return authorities;
  }

  @Override
  public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {

    Optional<IamAccount> account = repo.findByUsername(username);

    if (account.isPresent()) {
      IamAccount a = account.get();

      if (a.isActive()) {

        User u = new User(a.getUsername(), a.getPassword(), convertAuthorities(a));
        return u;

      } else {
        throw new DisabledException("User '" + username + "' is not active.");
      }
    }

    throw new UsernameNotFoundException("User '" + username + "' not found.");
  }

}
