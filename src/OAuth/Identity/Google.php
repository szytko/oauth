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
use Vegas\Security\OAuth\ServiceAbstract;
use Vegas\Security\OAuth\ServiceDecorator;

/**
 * Class Google
 *
 * @see https://developers.google.com/oauthplayground/
 *
 * @package Vegas\Security\OAuth\Identity
 */
class Google
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
        return 'google';
    }

    /**
     * @return Identity
     */
    public function getIdentity()
    {
        $response = $this->service->request('https://www.googleapis.com/oauth2/v1/userinfo');

        $identity = new Identity($this->getServiceName(), $response['email']);
        $identity->id = $response['id'];
        $identity->firstName = $response['given_name'];
        $identity->lastName = $response['family_name'];
        $identity->picture = $response['picture'];
        $identity->link = $response['link'];

        return $identity;
    }
}