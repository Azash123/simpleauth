<?php

namespace Apploud;

use Apploud\Password;


/**
 * Class SimpleAuth
 * @package Apploud
 */
class SimpleAuth
{
    /**
     * normal, whitelist, blacklist
     * @var string
     */
    private $mode = 'normal';


    /**
     * @var array
     */
    private $ipList = [];

    /**
     * @var array
     */
    private $auth = [];

    /**
     * @var bool
     */
    private $fbCrawlerAllowed;


    /**
     * @param $mode
     * @param bool $fbCrawlerAllowed
     * @throws \Exception
     */
    public function __construct($mode = 'normal', $fbCrawlerAllowed = true)
    {
        $this->setMode($mode);
        $this->fbCrawlerAllowed = $fbCrawlerAllowed;
    }

    /**
     * handles authorization
     */
    public function enforceAuthorization()
    {
        // check for fb user agent
        if ($this->fbCrawlerAllowed &&
            isset($_SERVER['HTTP_USER_AGENT']) &&
            in_array($_SERVER['HTTP_USER_AGENT'], ['facebookexternalhit/1.0', 'facebookexternalhit/1.1', 'Facebot'])) {
            return self::pass();
        }

        // check for whitelisted
        if ($this->mode === 'whitelist' && !in_array($_SERVER['REMOTE_ADDR'], $this->ipList)) {
            die('Your ip address is not among whitelisted ip addresses');
        }

        // check for blaclisted
        if ($this->mode === 'blacklist' && in_array($_SERVER['REMOTE_ADDR'], $this->ipList)) {
            die('Your ip address is among blacklisted ip addresses');
        }


        // authorization
        if (isset ($_SERVER['PHP_AUTH_USER'])
            && isset ($_SERVER['PHP_AUTH_PW'])
            && isset ($this->auth[$_SERVER['PHP_AUTH_USER']])
            && Password::verify($_SERVER['PHP_AUTH_PW'], $this->auth[$_SERVER['PHP_AUTH_USER']])
        ) {
            return self::pass();
        }

        header('WWW-Authenticate: Basic realm="private area"');
        header('HTTP/1.0 401 Unauthorized');

        exit ('You did not supply any or the wrong username/password combination');
    }

    /**
     * @param $ip
     */
    public function addIp($ip)
    {
        $ip = filter_var($ip, FILTER_VALIDATE_IP);

        if (!$ip) {
            throw new \Exception("Ip '$ip' is not a valid ip address");
        }

        $this->ipList[] = $ip;
    }


    /**
     * @param string $mode
     * @throws \Exception
     */
    public function setMode($mode = 'normal')
    {
        if (!in_array($mode, ['normal', 'blacklist', 'whitelist'])) {
            throw new \Exception("Unknown mode '$mode', allowed are: 'normal', 'whiterlist' and 'blacklist'");
        }

        $this->mode = $mode;
    }

    /**
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * @param array $credentials
     */
    public function addUser(array $credentials)
    {
        if (count($credentials) !== 1) {
            throw new \Exception('This method expects exactly one element in an array.');
        }

        $this->auth[key($credentials)] = Password::hash(array_shift($credentials));
    }

    /**
     * @param $name
     * @return bool
     */
    public function removeUser($name)
    {
        if (isset($this->auth[$name])) {
            unset($this->auth[$name]);
            return true;
        }

        return false;
    }

    /**
     * @return array
     */
    public function getListOfUsers()
    {
        return array_keys($this->auth);
    }

    /**
     * @param $user
     * @return bool
     */
    public function hasAccess($user)
    {
        return isset($this->auth[$user]);
    }

    /**
     * @return string
     */
    private static function pass()
    {
        return 'user';
    }
}
