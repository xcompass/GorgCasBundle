<?php


namespace Gorg\Bundle\CasBundle\Security\Firewall;


use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class CasUserToken extends AbstractToken
{
    /**
     * @param mixed $user
     * @param array $attributes
     * @param array $roles
     * @throws \InvalidArgumentException
     */
    public function __construct($user = null, $attributes = array(), $roles = array())
    {
        if (empty($roles) && $user instanceof UserInterface) $roles = $user->getRoles();
        parent::__construct($roles);
        $this->setUser($user);
        $this->setAttributes($attributes);
    }

    public function getCredentials()
    {
        return '';
    }
}