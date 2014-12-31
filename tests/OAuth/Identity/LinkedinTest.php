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

namespace Vegas\Tests\Security\OAuth\Identity;

use Vegas\Security\OAuth\Identity\Google;
use Vegas\Security\OAuth\Identity\Linkedin;

class LinkedinTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReturnValidIdentity()
    {
        $mockData = [
            'emailAddress' => 'test@test.com',
            'id' => 1234,
            'firstName' => 'First',
            'lastName' => 'Last',
            'pictureUrl' => 'picture.jpg',
            'publicProfileUrl' => 'www.test.com'
        ];
        $mockBuilder = $this->getMockBuilder('\Vegas\Security\OAuth\ServiceDecorator');
        $mockBuilder->disableOriginalConstructor();
        $service = $mockBuilder->getMock();
        $service->expects($this->any())
            ->method('request')
            ->willReturn($mockData);

        $identity = new Linkedin($service);
        $data = $identity->getIdentity();

        $this->assertEquals($data->email, $mockData['emailAddress']);
        $this->assertEquals($data->id, $mockData['id']);
        $this->assertEquals($data->firstName, $mockData['firstName']);
        $this->assertEquals($data->lastName, $mockData['lastName']);
        $this->assertEquals($data->picture, $mockData['pictureUrl']);
        $this->assertEquals($data->link, $mockData['publicProfileUrl']);
    }
} 