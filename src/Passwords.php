<?php

namespace Apploud;

/**
 * Class Password
 * @package Apploud
 */
class Password
{
    /**
     *
     */
    const SALT = 'opdai23e29d9c';

    /**
     * @param $password
     * @return string
     */
    public static function hash($password)
    {
        return sha1(md5($password));
    }

    /**
     * @param $password
     * @param $hash
     * @return bool
     */
    public static function verify($password, $hash)
    {
        return self::hash($password) === $hash;
    }
}
