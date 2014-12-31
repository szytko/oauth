<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */ 

namespace Vegas\Tests\Security\OAuth;

use Vegas\Security\OAuth\Identity;

class IdentityTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldContainEmailAndService()
    {
        $identity = new Identity('facebook', 'test@test.com');
        $this->assertEquals($identity->getEmail(), 'test@test.com');
        $this->assertEquals($identity->getService(), 'facebook');
        $this->assertEquals('test@test.com', (string) $identity);
    }

    public function testShouldReturnArrayOfValues()
    {
        $identity = new Identity('facebook', 'test@test.com');
        $this->assertSame(['service' => 'facebook', 'email' => 'test@test.com'], $identity->toArray());
    }

    public function testShouldSerializeToJson()
    {
        $identity = new Identity('facebook', 'test@test.com');

        $this->assertEquals(
            json_encode(['service' => 'facebook', 'email' => 'test@test.com']),
            json_encode($identity)
        );
    }

    public function testShouldCallMagicSetterAndGetter()
    {
        $identity = new Identity('facebook', 'test@test.com');

        $identity->setEmail('test@test2.com');
        $this->assertEquals('test@test2.com', $identity->getEmail());
        $identity->setService('google');
        $this->assertEquals('google', $identity->getService());

        $identity->setFirstName('John');
        $this->assertEquals('John', $identity->getFirstName());

        $this->assertArrayHasKey('firstName', $identity->toArray());

        $this->assertNull($identity->getMiddleName());
    }

    public function testShouldThrowExceptionForInvalidMethod()
    {
        $identity = new Identity('test', 'test@test.com');

        try {
            $identity->fake();

            throw new \Exception();
        } catch (\Exception $e) {
            $this->assertInstanceOf('\BadMethodCallException', $e);
        }
    }

    public function testShouldAccessMagicProperty()
    {
        $identity = new Identity('facebook', 'test@test.com');

        $identity->email = 'test@test2.com';
        $this->assertEquals($identity->email, $identity->getEmail());

        $identity->lastName = 'Dot';
        $this->assertEquals($identity->lastName, $identity->getLastName());

        $this->assertArrayHasKey('lastName', $identity->toArray());

        $this->assertNull($identity->fake);
    }

    public function testShouldProvideArrayAccess()
    {
        $identity = new Identity('facebook', 'test@test.com');

        $this->assertEquals('facebook', $identity['service']);
        $this->assertEquals('test@test.com', $identity['email']);
        $this->assertTrue(isset($identity['email']));

        unset($identity['email']);
        $this->assertArrayNotHasKey('email', $identity);

        $identity['service'] = 'google';
        $this->assertEquals('google', $identity->getService());
    }
}
 