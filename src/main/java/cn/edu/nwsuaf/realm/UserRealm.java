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
import org.apache.shiro.cas.CasRealm;
import org.apache.shiro.crypto.hash.Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class UserRealm extends CasRealm {

    /**
     * 设置用户角色和权限
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        SimpleAuthorizationInfo info = (SimpleAuthorizationInfo) super.doGetAuthorizationInfo(principals);

        // 根据用户名查询当前用户拥有的角色
//        Set<Role> roles = userService.findRoles(username);
        Set<String> roleNames = new HashSet<String>();
//        for (Role role : roles) {
            roleNames.add("ROLE_USER");
//        }
//        // 将角色名称提供给info
        info.getRoles().add("ROLE_ADMIN");
//        // 根据用户名查询当前用户权限
//        Set<Permission> permissions = userService.findPermissions(username);
//        Set<String> permissionNames = new HashSet<String>();
//        for (Permission permission : permissions) {
//            permissionNames.add(permission.getPermission());
//        }
        // 将权限名称提供给info
//        authorizationInfo.setStringPermissions(permissionNames);

        return info;
    }

    /**
     * 用户验证信息
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        return super.doGetAuthenticationInfo(token);
    }
}
