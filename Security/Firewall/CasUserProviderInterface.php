<?php


namespace Gorg\Bundle\CasBundle\Security\Firewall;


use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

interface CasUserProviderInterface extends UserProviderInterface {
    public function createUser(TokenInterface $token);
}