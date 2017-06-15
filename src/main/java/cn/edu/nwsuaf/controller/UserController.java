package cn.edu.nwsuaf.controller;

import com.alibaba.fastjson.JSON;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/user")
public class UserController {
    // 用户登陆提交
    @RequestMapping("/toLogin")
    public String loginsubmit(Model model, HttpServletRequest request)
            throws Exception {

        // shiro在认证过程中出现错误后将异常类路径通过request返回
        String exceptionClassName = (String) request.getAttribute("shiroLoginFailure");
        if (exceptionClassName != null) {
            if (UnknownAccountException.class.getName().equals(
                    exceptionClassName)) {
                throw new Exception("账号不存在");
            } else if (IncorrectCredentialsException.class.getName().equals(
                    exceptionClassName)) {
                throw new Exception("用户名/密码错误");
            } else if ("randomCodeError".equals(exceptionClassName)) {
                throw new Exception("验证码错误");
            } else {
                throw new Exception();// 最终在异常处理器生成未知错误
            }
        } else {
            return "index";
        }
    }

    // 系统首页
    @RequestMapping("/index")
    public ModelAndView index(ModelMap map) {
        Subject subject = SecurityUtils.getSubject();
        System.out.println(JSON.toJSONString(subject.getPrincipal()));
        return new ModelAndView("index");
    }

}
