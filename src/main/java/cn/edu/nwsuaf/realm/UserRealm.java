package cn.edu.nwsuaf.realm;

import cn.edu.nwsuaf.matcher.RetryLimitHashedCredentialsMatcher;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class UserRealm extends AuthorizingRealm {
    // 用户对应的角色信息与权限信息都保存在数据库中，通过UserService获取数据
//    private UserService userService = new UserServiceImpl();
    @Autowired
    private RetryLimitHashedCredentialsMatcher retryLimitHashedCredentialsMatcher;

    private String passwordRetryCache;

    /**
     * 提供用户信息返回权限信息
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        // 根据用户名查询当前用户拥有的角色
//        Set<Role> roles = userService.findRoles(username);
        Set<String> roleNames = new HashSet<String>();
//        for (Role role : roles) {
            roleNames.add("ROLE_USER");
//        }
//        // 将角色名称提供给info
        authorizationInfo.setRoles(roleNames);
//        // 根据用户名查询当前用户权限
//        Set<Permission> permissions = userService.findPermissions(username);
//        Set<String> permissionNames = new HashSet<String>();
//        for (Permission permission : permissions) {
//            permissionNames.add(permission.getPermission());
//        }
        // 将权限名称提供给info
//        authorizationInfo.setStringPermissions(permissionNames);

        return authorizationInfo;
    }

    /**
     * 提供账户信息返回认证信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
//        User user = userService.findByUsername(username);
//        if (user == null) {
//            // 用户名不存在抛出异常
//            throw new UnknownAccountException();
//        }
//        if (user.getLocked() == 0) {
//            // 用户被管理员锁定抛出异常
//            throw new LockedAccountException();
//        }
        setPasswordRetryCache();
        Hash password = retryLimitHashedCredentialsMatcher.hashProvidedCredentials("123456",
                null, retryLimitHashedCredentialsMatcher.getHashIterations());
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username,
                password, getName());
        return authenticationInfo;
    }

    @Override
    public boolean supports(AuthenticationToken token){
        return token != null;
    }

    public void setPasswordRetryCache(String passwordRetryCache){
        this.passwordRetryCache = passwordRetryCache;
    }

    public void setPasswordRetryCache() {
        if(retryLimitHashedCredentialsMatcher == null
                || retryLimitHashedCredentialsMatcher.getPasswordRetryCache() != null){
            return;
        }
        CacheManager cacheManager = getCacheManager();
        Cache<String, AtomicInteger> passwordCache = cacheManager.getCache(this.passwordRetryCache);
        if(passwordCache != null) {
            retryLimitHashedCredentialsMatcher.setPasswordRetryCache(passwordCache);
        }
    }
}
