<?php 

// namespace GoBuyPHPEncryption\Src;
trait ChainOfTrust
{

    // Configuration for the private key
private $configArgs = [
    "digest_alg" => "sha512",
    "private_key_bits" => 4096,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];

// Distinguished Name for the root CA
private $rootCADN = [
    "countryName" => "US",
    "stateOrProvinceName" => "Massachusetts",
    "localityName" => "Waltham",
    "organizationName" => "GoBuy",
    "organizationalUnitName" => "GoBuy Data Security",
    "commonName" => "gobuy.com",
    "emailAddress" => "security@gobuy.com"
];

/**
 * Generates a new private key.
 *
 * @param array $configArgs Configuration for generating the private key.
 * @return resource The private key resource.
 */
public function generatePrivateKey($configArgs = []) {
    // Generate a new private key
    $privateKey = openssl_pkey_new($configArgs);
    if (!$privateKey) {
        die('Failed to generate private key: ' . openssl_error_string());
    }
    return $privateKey;
}

/**
 * Generates a CSR (Certificate Signing Request).
 *
 * @param array $dn The Distinguished Name to be used in the CSR.
 * @param resource $privateKey The private key resource.
 * @return string The CSR data.
 */
public function generateCSR(Array $dn, string $privateKey) {
    
    // Generate a CSR
    $csr = openssl_csr_new($dn, $privateKey);
    if (!$csr) {
        die('Failed to generate CSR: ' . openssl_error_string());
    }
    return $csr;

}

/**
 * Self-signs the CSR to create a root CA certificate.
 *
 * @param resource $csr The CSR resource.
 * @param int $days The number of days to certify the certificate for.
 * @param array $configArgs Configuration for generating the certificate.
 * @return string The certificate data.
 */
public function selfSignCSR($csr, $days, $configArgs = []) {
    // Self-sign the CSR to create a root CA certificate
    $caCert = openssl_csr_sign($csr, null, $csr, $days, $configArgs);
    if (!$caCert) {
        die('Failed to self-sign the CSR: ' . openssl_error_string());
    }
    return $caCert;
}

/**
 * Signs a CSR with the CA's certificate and private key to create an intermediate or end-entity certificate.
 *
 * @param resource|string $csr The CSR resource.
 * @param resource|string $caCert The CA's certificate resource.
 * @param resource|string $caPrivateKey The CA's private key resource.
 * @param int $days The number of days to certify the certificate for.
 * @param array $configArgs Configuration for generating the certificate.
 * @return string The certificate data.
 */
public function signCSR($csr, $caCert, $caPrivateKey, $days, $configArgs = []) {
    // Sign the CSR with the CA's certificate and private key
    $cert = openssl_csr_sign($csr, $caCert, $caPrivateKey, $days, $configArgs);
    if (!$cert) {
        die('Failed to sign the CSR: ' . openssl_error_string());
    }

    return $cert;
}




// Generate the intermediate CA's private key and CSR
// $intermediateCAPrivateKey = generatePrivateKey($configArgs);
// $intermediateCACSR = generateCSR($intermediateCADN, $intermediateCAPrivateKey);

// // Sign the intermediate CA's CSR with the root CA's certificate and private key
// $intermediateCACert = signCSR($intermediateCACSR, $rootCACert, $rootCAPrivateKey, 365, $configArgs);

// // Export the certificates and private keys to files
// openssl_pkey_export_to_file($rootCAPrivateKey, 'root_ca_private_key.pem');
// openssl_pkey_export_to_file($intermediateCAPrivateKey, 'intermediate_ca_private_key.pem');
// openssl_x509_export_to_file($rootCACert, 'root_ca_cert.pem');
// openssl_x509_export_to_file($intermediateCACert, 'intermediate_ca_cert.pem');


    
}