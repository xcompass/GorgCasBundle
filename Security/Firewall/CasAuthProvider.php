<?php


namespace Gorg\Bundle\CasBundle\Security\Firewall;

use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\HttpKernel\Log\LoggerInterface;

class CasAuthProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $userChecker;
    private $defaultRoles;
    private $logger;

    public function __construct(UserProviderInterface $userProvider,
                                UserCheckerInterface $userChecker, LoggerInterface $logger = null)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->logger = $logger;
        $this->defaultRoles = array('ROLE_USER');
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }
        if (!$user = $token->getUser()) {
            throw new BadCredentialsException(
                'No pre-authenticated CAS principal found in request.');
        }
        try {
            $user = $this->retrieveUser($token);
            $this->checkAuthentication($user, $token);
            if ($user instanceof UserInterface) {
                $this->userChecker->checkPostAuth($user);
            }
            $roles = $this->mergeRoles($token->getRoles(), $user->getRoles());
            $authenticatedToken = new CasUserToken($user, $token->getAttributes(), $roles);
            $authenticatedToken->setAuthenticated(true);
            if (null !== $this->logger)
                $this->logger->debug(
                    sprintf('CasAuthProvider: authenticated token: %s', $authenticatedToken)
                );

            return $authenticatedToken;
        } catch (UsernameNotFoundException $notFound) {
            throw $notFound;
        }
    }

    public function checkAuthentication($user, $token)
    {
        return true;
    }

    public function retrieveUser($token)
    {
        try {
            $user = $this->userProvider
                ->loadUserByUsername($token->getUsername());
            if (null !== $this->logger)
                $this->logger->debug(
                    sprintf('ShibbolethAuthProvider: userProvider returned: %s', $user->getUsername())
                );
            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException(
                    'The user provider must return a UserInterface object.');
            }
        } catch (UsernameNotFoundException $notFound) {
            if ($this->userProvider instanceof CasUserProviderInterface) {
                $user = $this->userProvider->createUser($token);
                if ($user === null) {
                    $user = $token->getUsername();
                }
            } else {
                throw $notFound;
            }
        }
        return $user;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof CasUserToken;
    }

    private function mergeRoles($roles1, $roles2) {
        $roles = array_merge($roles1, $roles2);
        $result = array_map("unserialize", array_unique(array_map("serialize", $roles)));

        return $result;
    }
}