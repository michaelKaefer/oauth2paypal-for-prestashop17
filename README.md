```php
<?php

require 'vendor/autoload.php';

$paypalProvider = new MichaelKaefer\OAuth2PaypalForPrestashop17\Stevenmaguire\OAuth2\Client\Provider\Paypal([
    'clientId'          => '{paypal-client-id}',
    'clientSecret'      => '{paypal-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url',
    'isSandbox'         => true, // Optional, defaults to false. When true, client uses sandbox urls.
]);

// Get authorization code
if (!isset($_GET['code'])) {
    // Get authorization URL
    $options = [
        'scope' => ['openid', 'profile', 'email', 'phone', 'address']
    ];
    $authorizationUrl = $paypalProvider->getAuthorizationUrl($options);

    // Get state and store it to the session
    $_SESSION['oauth2state'] = $paypalProvider->getState();

    // Redirect user to authorization URL
    header('Location: ' . $authorizationUrl);
    exit;
// Check for errors
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {
    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }
    exit('Invalid state');
} else {
    // Get access token
    try {
        $accessToken = $paypalProvider->getAccessToken(
            'authorization_code',
            [
                'code' => $_GET['code']
            ]
        );
    } catch (\MichaelKaefer\OAuth2ClientForPrestashop17\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        exit($e->getMessage());
    }

    // Get resource owner
    try {
        $resourceOwner = $paypalProvider->getResourceOwner($accessToken);
    } catch (\MichaelKaefer\OAuth2ClientForPrestashop17\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        exit($e->getMessage());
    }
        
    // Now you can store the results to session ...
    $_SESSION['accessToken'] = $accessToken;
    $_SESSION['resourceOwner'] = $resourceOwner;
        
    var_dump($accessToken, $resourceOwner);
}
```