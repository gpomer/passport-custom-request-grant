<?php

namespace MikeMcLin\Passport;

use Illuminate\Http\Request;
use Laravel\Passport\Bridge\User;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class CustomRequestGrant extends AbstractGrant
{

    /**
     * @param UserRepositoryInterface         $userRepository
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(
        UserRepositoryInterface $userRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    )
    {
        $this->setUserRepository($userRepository);
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->refreshTokenTTL = new \DateInterval('P1M');
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    )
    {
        // Validate request
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request));
        $rp = (array) $request->getParsedBody();

        if(array_key_exists("email",$rp) && array_key_exists("password",$rp)) {
            $user = $this->validateUser($request);
            $user_id = $user->getIdentifier();
        } else if(array_key_exists("client_id",$rp) && array_key_exists("client_secret",$rp)) {
            $model = config('auth.providers.users.model');
            $user_data = \DB::select("select user_id from oauth_clients where id=? AND secret=?",[$rp["client_id"],$rp["client_secret"]]);
            $user = $model::find($user_data[0]->user_id);
            if(!isset($user->id)) {
                throw OAuthServerException::invalidCredentials();
            } else
                $user_id = $user->id;
        } else
            throw OAuthServerException::invalidCredentials();

        if(array_key_exists("client_id",$rp) && array_key_exists("client_secret",$rp)) {
            $client = $this->validateClient($request);
        } else if($user_id) {
            $client_keys = \DB::select("select id, secret from oauth_clients where user_id=?",[$user_id]);

            if(!isset($client_keys) || empty($client_keys))
                throw OAuthServerException::invalidCredentials();

            $client = $this->clientRepository->getClientEntity(
                $client_keys[0]->id,
                $this->getIdentifier(),
                $client_keys[0]->secret,
                true
            );
        } else
            throw OAuthServerException::invalidCredentials();

        // Finalize the requested scopes
        $scopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $user_id);

        // Issue and persist new tokens
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $user_id, $scopes);
        $refreshToken = $this->issueRefreshToken($accessToken);

        // Inject tokens into response
        $responseType->setAccessToken($accessToken);
        $responseType->setRefreshToken($refreshToken);

        return $responseType;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'custom_request';
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return UserEntityInterface
     * @throws OAuthServerException
     */
    protected function validateUser(ServerRequestInterface $request)
    {
        $laravelRequest = new Request($request->getParsedBody());

        $user = $this->getUserEntityByRequest($laravelRequest);

        if ($user instanceof UserEntityInterface === false) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::USER_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidCredentials();
        }

        return $user;
    }

    /**
     * Retrieve user by request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Laravel\Passport\Bridge\User|null
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function getUserEntityByRequest(Request $request)
    {

        if (is_null($model = config('auth.providers.users.model'))) {
            throw OAuthServerException::serverError('Unable to determine user model from configuration.');
        }

        if (method_exists($model, 'byPassportCustomRequest')) {
            $user = (new $model)->byPassportCustomRequest($request);
        } else {
            throw OAuthServerException::serverError('Unable to find byPassportCustomRequest method on user model.');
        }

        return ($user) ? new User($user->id) : null;
    }
}
