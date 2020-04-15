<?php
/**
 * parent class of users access
 * @author: Gabriel Malaquias
 * @email: g@gmalaquias.com
 * @site: gmalaquias.com
 * @date: 30/04/2015 21:37
 */

namespace Alcatraz\Security;

/**
 * Classe alterada para uso no alcatraz-boilerplate
 */

use Alcatraz\Annotation\Annotation;
use Alcatraz\Components\Session\Session;
use Alcatraz\Kernel\Request;
use Alcatraz\Kernel\Router;
use Alcatraz\Owl\Owl;
use BLL\PersonBLL;
use BLL\Users\UserBLL;
use Entities\Users;

class Security {

    private static $user;
    private static $personId;

    public static function login($login, $pass){

        if(self::verifyLogin($login,$pass, true)){
            Session::set("login", $login);
            Session::set("password", self::encrypt($pass));
            UserBLL::UpdateLastAccessByLogin($login);
            UserBLL::UpdateLastIpByLogin($login);

            return true;
        }

        return false;
    }

    public static function logout(){
        Session::destroy();
    }

    /**
     * @param bool $ignoreAnnotations = Ignora informações de annotations do controller para verificar session
     * @return bool
     * @throws \Alcatraz\Annotation\AnnotationException
     */
    public static function verifySession($ignoreAnnotations = false){

        Session::start();
        $annotation = new Annotation(Router::$controller);
        $prop = $annotation->getAnnotationsByMethod(Request::getAction());

        $login = Session::get("login");
        $pass = Session::get("password");
        $profile = Session::get("profile");

        if($ignoreAnnotations)
            return self::verifyLogin($login,$pass);

        if(isset($prop["AllowUsers"])){
            return self::verifyLogin($login,$pass) && $profile != null;
        }elseif(!isset($prop["AllowAccess"])){
            return self::verifyLogin($login,$pass) && self::verifyAccess($profile);
        }

        return true;
    }

    /**
     * @return int
     */
    public static function getProfileActive(){
        return Session::get("profile");
    }

    /**
     * @return int
     */
    public static function getEmpresaActive(){
        return Session::get("empresaId");
    }

    /**
     * @param bool $obj
     * @return Entities\PersonUser
     */
    public static function getUser($obj = true){
        if(self::verifySession())
            return $obj ? self::$user : self::$user->login;

        return null;
    }

    public static function getProfiles($login){

        $owl = new Owl();

        $profiles = $owl->Get("PersonUser")
            ->Join("PersonUserProfile", "pu.id", "pup.personUserId")
            ->Join("Profile", "p.id", "pup.profileId")
            ->LeftJoin("Person","person.id", "pup.empresaId")
            ->Where("login = '" . $login . "' and pup.disabled = 0")
            ->Where("person.status = 1 OR person.status is null")
            ->Select("p.*, person.id as empresaId, person.name, pup.id as personuserprofileid")
            ->ToList();

        return $profiles;
    }

    public static function verifyLoginAndProfile($login, $profileId){
        $owl = new Owl();

        $profiles = $owl->Get("PersonUser")
            ->Join("PersonUserProfile", "pu.id", "pup.personUserId")
            ->Join("Profile", "p.id", "pup.profileId")
            ->LeftJoin("Person","person.id", "pup.empresaId")
            ->Where("login = '" . $login . "'  and disabled = 0 AND pup.id = ". $profileId)
            ->Select("p.*, person.id as empresaId, person.name, pup.id as personuserprofileid")
            ->FirstOrDefault();

        return $profiles;
    }

    public  static function setProfile ($profileId, $empresaId){
        Session::start();
        Session::set("profile", $profileId);
        Session::set("empresaId", $empresaId);
    }

    public static function getEmpresaLogada(){
        $empresa = self::getEmpresaActive();
        if($empresa != null)
            return PersonBLL::getPersonById($empresa);

        return null;
    }

    public static function getPersonId(){
        return self::$personId;
    }

    private static function verifyLogin($login, $pass, $encrypt = false){

        Session::start();

        if($encrypt)
            $pass = self::encrypt($pass);

        $owl = new Owl();
        $user = $owl->Get("PersonUser", null, "Person")->Where("login = ? AND password =  ?", array($login, $pass))->FirstOrDefault();

        if($user != null) {
            self::$personId = $user->_Person->id;
            self::$user = $user;
            Session::set("creationDate",$user->creationDate);

            //update last activity
            UserBLL::UpdateLastActivityByLogin($login);

            return true;
        }

        self::$user = null;
        return false;

    }

    private static function verifyAccess($profile){
        $router["area"] = Request::getArea();
        $router["controller"] = Request::getController();
        $router["action"] = Request::getAction();

        $profileId = self::getProfileActive();

        $owl = new Owl();
        $access = $owl->Get("ProfileMenu")->Join("Menu","p.menuid", "m.id")
            ->Where("p.profileId = $profileId")
            ->Where("(m.controller = '".$router["controller"]."' AND m.action = '".$router["action"]."')")
            ->WhereOR("m.area = '".$router["area"]."' AND m.controller = '".$router["controller"]."' AND m.action = '".$router["action"]."'")
            ->Select("m.id")->FirstOrDefault();

        return $access != null;
    }

    public static function encrypt($pass){
        $pass = md5(md5(md5(md5(md5(md5($pass)."bfcc0a49a2b44212bee50974c79782da")))));
        return $pass;
    }


}