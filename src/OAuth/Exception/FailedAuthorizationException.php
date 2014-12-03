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
 
namespace Vegas\Security\OAuth\Exception;

use \Vegas\Security\OAuth\Exception as OAuthException;

/**
 * Class FailedAuthorizationException
 * @package Vegas\Security\OAuth\Exception
 */
class FailedAuthorizationException extends OAuthException
{
    protected $message = 'Authorization process was failed';
} 