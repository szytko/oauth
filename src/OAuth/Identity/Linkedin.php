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
 
namespace Vegas\Security\OAuth\Identity;

use Vegas\Security\OAuth\Identity;
use Vegas\Security\OAuth\ServiceDecorator;

/**
 * Class Linkedin
 *
 * @see https://developer.linkedin.com/documents/authentication
 *
 * @package Vegas\Security\OAuth\Identity
 */
class Linkedin
{
    /**
     * @var ServiceDecorator
     */
    protected $service;

    /**
     * @param ServiceDecorator $service
     */
    public function __construct(ServiceDecorator $service)
    {
        $this->service = $service;
    }

    /**
     * {@inheritdoc}
     */
    public function getServiceName()
    {
        return 'linkedin';
    }

    /**
     * @return Identity
     */
    public function getIdentity()
    {
        $response = $this->service->request('/people/~:(id,first-name,last-name,email-address,picture-url,public-profile-url)?format=json');

        $identity = new Identity($this->getServiceName(), $response['emailAddress']);
        $identity->id = $response['id'];
        $identity->firstName = $response['firstName'];
        $identity->lastName = $response['lastName'];
        $identity->picture = !isset($response['pictureUrl']) ? '' : $response['pictureUrl'];
        $identity->link = $response['publicProfileUrl'];


        return $identity;
    }
}