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

namespace Vegas\Tests\Security\OAuth;

use Phalcon\DI;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth;

class OAuthTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        parent::setUp();
        $_SERVER['REQUEST_URI'] = '/login';
    }

    public function testShouldCreateServiceByItsName()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf(
            '\Vegas\Security\OAuth\Service\Linkedin',
            $oauth->obtainServiceInstance('linkedin')
        );
    }

    public function testShouldThrowExceptionForInvalidServiceName()
    {
        $oauth = new OAuth();

        try {
            $oauth->obtainServiceInstance('fake');

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\Vegas\Security\OAuth\Exception\ServiceNotFoundException', $e);
        }
    }

    public function testShouldReturnDefaultTokenStorage()
    {
        $oauth = new OAuth();

        $this->assertInstanceOf('\OAuth\Common\Storage\Memory', $oauth->getDefaultTokenStorage());
    }

    public function testShouldChangeTokenStorage()
    {
        $oauth = new OAuth();
        $oauth->setTokenStorage(new OAuth\Storage\Session());

        $this->assertInstanceOf('\Vegas\Security\OAuth\Storage\Session', $oauth->getTokenStorage());
    }

    public function testShouldSetTokenStorageFromConstructor()
    {
        $oauth = new OAuth(new OAuth\Storage\Session());

        $this->assertInstanceOf('\Vegas\Security\OAuth\Storage\Session', $oauth->getTokenStorage());
    }
} 