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

/**
 * Class Facebook
 *
 * @see https://developer.linkedin.com/documents/authentication
 *
 * @package Vegas\Security\OAuth\Service
 */
class Facebook implements \IdentityInterface
{
    /**
     * Name of oAuth service
     */
    const SERVICE_NAME = 'facebook';

    /**
     * @return Identity
     */
    public function getIdentity()
    {
        $response = $this->request('/me?fields=id,first_name,last_name,picture,link,email');

        $identity = new Identity($this->getServiceName(), $response['email']);
        $identity->id = $response['id'];
        $identity->firstName = $response['first_name'];
        $identity->lastName = $response['last_name'];
        $identity->picture = $response['picture']['data']['url'];
        $identity->link = $response['link'];

        return $identity;
    }
}