package cn.edu.nwsuaf.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {
//    @Autowired
//    private UserService userService;

//    @RequestMapping("login")
//    public ModelAndView login(String username, String password) {
//        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
//        Subject subject = SecurityUtils.getSubject();
//        try {
//            subject.login(token);
//        } catch (IncorrectCredentialsException ice) {
//            // 捕获密码错误异常
//            ModelAndView mv = new ModelAndView("error");
//            mv.addObject("message", "password error!");
//            return mv;
//        } catch (UnknownAccountException uae) {
//            // 捕获未知用户名异常
//            ModelAndView mv = new ModelAndView("error");
//            mv.addObject("message", "username error!");
//            return mv;
//        } catch (ExcessiveAttemptsException eae) {
//            // 捕获错误登录过多的异常
//            ModelAndView mv = new ModelAndView("error");
//            mv.addObject("message", "times error");
//            return mv;
//        }
////        User user = userService.findByUsername(username);
//        subject.getSession().setAttribute("user", username);
//        return new ModelAndView("success");
//    }

    @RequestMapping
    public String index(){
        return "index";
    }

    @RequestMapping("success")
    public String success(){
        return "success";
    }

    @RequestMapping("error")
    public String error(){
        return "error";
    }
}
