<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawek@amsterdam-standard.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Security\OAuth;

/**
 * Simple class for object representation identity
 *
 * @package Vegas\Security\Authentication
 */
class Identity implements \JsonSerializable, \ArrayAccess
{
    /**
     * Identity values
     *
     * @var array
     */
    private $values = array();

    /**
     *
     * @param $service
     * @param $email
     */
    public function __construct($service, $email)
    {
        $this->values['service'] = $service;
        $this->values['email'] = $email;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return $this->values['email'];
    }

    /**
     * @return string
     */
    public function getService()
    {
        return $this->values['service'];
    }

    /**
     * @param $name
     * @param $value
     */
    public function __set($name, $value)
    {
        $this->values[$name] = $value;
    }

    /**
     * Makes identity values accessible as object property
     * For example for get user ID
     * <code>
     * echo $identity->id;
     * </code>
     *
     * @param $name
     * @return null
     */
    public function __get($name)
    {
        return isset($this->values[$name]) ? $this->values[$name] : null;
    }


    /**
     * Makes identity values accessible by method calling
     * For example for get user ID
     * <code>
     * echo $identity->getId();
     * </code>
     *
     * @param $name
     * @param $args
     * @throws \BadMethodCallException
     * @return null
     */
    public function __call($name, $args)
    {
        if (strpos($name, 'get') !== false) {
            $name = lcfirst(str_replace('get', '', $name));
            if (!isset($this->values[$name])) {
                return null;
            }

            return $this->values[$name];
        }

        if (strpos($name, 'set') !== false) {
            $name = lcfirst(str_replace('set', '', $name));
            $this->values[$name] = $args[0];

            return $this;
        }

        throw new \BadMethodCallException($name);
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->values;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->getEmail();
    }

    /**
     * (PHP 5 &gt;= 5.4.0)<br/>
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * (PHP 5 &gt;= 5.0.0)<br/>
     * Whether a offset exists
     * @link http://php.net/manual/en/arrayaccess.offsetexists.php
     * @param mixed $offset <p>
     * An offset to check for.
     * </p>
     * @return boolean true on success or false on failure.
     * </p>
     * <p>
     * The return value will be casted to boolean if non-boolean was returned.
     */
    public function offsetExists($offset)
    {
        return isset($this->values[$offset]);
    }

    /**
     * (PHP 5 &gt;= 5.0.0)<br/>
     * Offset to retrieve
     * @link http://php.net/manual/en/arrayaccess.offsetget.php
     * @param mixed $offset <p>
     * The offset to retrieve.
     * </p>
     * @return mixed Can return all value types.
     */
    public function offsetGet($offset)
    {
        return $this->values[$offset];
    }

    /**
     * (PHP 5 &gt;= 5.0.0)<br/>
     * Offset to set
     * @link http://php.net/manual/en/arrayaccess.offsetset.php
     * @param mixed $offset <p>
     * The offset to assign the value to.
     * </p>
     * @param mixed $value <p>
     * The value to set.
     * </p>
     * @return void
     */
    public function offsetSet($offset, $value)
    {
        $this->values[$offset] = $value;
    }

    /**
     * (PHP 5 &gt;= 5.0.0)<br/>
     * Offset to unset
     * @link http://php.net/manual/en/arrayaccess.offsetunset.php
     * @param mixed $offset <p>
     * The offset to unset.
     * </p>
     * @return void
     */
    public function offsetUnset($offset)
    {
        unset($this->values[$offset]);
    }
}