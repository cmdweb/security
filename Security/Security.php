<?php
/**
 * parent class of users access
 * @author: Gabriel Malaquias
 * @email: g@gmalaquias.com
 * @site: gmalaquias.com
 * @date: 30/04/2015 21:37
 */

namespace Alcatraz\Security;

use Alcatraz\Annotation\Annotation;
use Alcatraz\Components\Session\Session;
use Alcatraz\Kernel\Request;
use Alcatraz\Kernel\Router;
use Alcatraz\Owl\Owl;
use Entities\Users;

class Security {

    private static $user;

    public static function login($login, $pass){

        if(self::verifyLogin($login,$pass, true)){
            Session::set("login", $login);
            Session::set("pass", self::encrypt($pass));
            return true;
        }

        return false;
    }

    public static function logout(){
        Session::destroy();
    }

    public static function verifySession(){

        Session::start();

        $annotation = new Annotation(Router::$controller);

        $prop = $annotation->getAnnotationsByMethod(Request::getAction());

        if(!isset($prop["AllowAccess"])) {

            $login = Session::get("login");
            $pass = Session::get("pass");

            return self::verifyLogin($login, $pass, false);
        }
        return true;
    }

    public static function getUser($obj = true){
        if(self::verifySession())
            return $obj ? self::$user : self::$user->login;

        return null;
    }

    public static function insertUser($login, $pass){
        $user = new Users();

        $user->login = $login;
        $user->pass = $pass;
        $user->activated = 1;

        $owl = new Owl();
        $owl->Insert($user);
        $owl->Save();
    }

    private static function verifyLogin($login, $pass, $encrypt = false){

        Session::start();

        if($encrypt)
            $pass = self::encrypt($pass);

        $owl = new Owl();
        $user = $owl->Get("Users")->Where("login = '" . $login . "' AND pass = '" . $pass . "' AND activated = '1'")->FirstOrDefault();

        if($user != null) {
            self::$user = $user;
            return true;
        }

        self::$user = null;
        return false;

    }

    private static function encrypt($pass){
        $pass = md5($pass);
        return $pass;
    }
}