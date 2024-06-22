<?php
namespace GoBuy\Encryption;
class DiffieHellman {
    private $privateKey;
    private $publicKey;
    
    public function __construct() {
        $config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
        );
        
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $this->privateKey);
        $details = openssl_pkey_get_details($res);
        $this->publicKey =$details['key'];

        // echo "pKy: ". $this->privateKey. "  pubK: ". $this->publicKey;
    }
    
    public function getPublicKey() {
        return $this->publicKey;
    }

    public function computeSharedSecret($otherPartyPublicKey) {
        openssl_private_decrypt($otherPartyPublicKey, $sharedSecret, $this->privateKey);
        return $sharedSecret;
    }

    public function authenticateSharedSecret($bobSharedSecret) {
        $signature = '';
        openssl_sign($bobSharedSecret, $signature, $this->privateKey);        
        return openssl_verify($bobSharedSecret, $signature, $this->publicKey);
    }
}

// Example usage
$bob = new DiffieHellman();

$aliceSharedSecret = $alice->computeSharedSecret($bob->getPublicKey());
$bobSharedSecret = $bob->computeSharedSecret($alice->getPublicKey());

if ($aliceSharedSecret === false) {
    echo "Encryption error: " . openssl_error_string(). "<br />";
    exit;
}
// Authenticate shared secrets
if ($aliceSharedSecret === $bobSharedSecret) {
    $bob->authenticateSharedSecret($bobSharedSecret);
    echo "Shared secrets authenticated successfully." . $alice->authenticateSharedSecret($aliceSharedSecret);
} else {
    echo "Shared secrets did not authenticate. " . $bobSharedSecret;
}