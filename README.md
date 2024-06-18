

# CMS Signer Library

The CMS Signer Library is a PHP utility for signing files using Cryptographic Message Syntax (CMS). It provides a simple interface to sign data and ensure its integrity and authenticity.

## Features

- Easy-to-use CMS/PKCS7 signing, encrypting, decrypting and signature-verifying functionality
- Built-in logging with Monolog
- Exception handling for robust error management

## Requirements

- PHP 7.4 or higher
- OpenSSL extension enabled
- Composer for dependency management

## Installation

Use Composer to install the library:

```bash
composer require gobuy/gobuy_php_encryption
```

## Usage

To use the CMS Signer, you need to include the Composer autoload file and start invoking class members with the instance `$gobuy`  class name is `GoBuyEncryption` incase you prefer a different class object name. The class constructor takes no argument.

```php

require 'vendor/autoload.php'; 

```

## Usage

Check if OpenSSL module is loaded.

```php

// Load the OpenSSL module
if (!extension_loaded('openssl')) {
    die('OpenSSL extension is not loaded.');
}

```

#### To sign a file
You must set the necessary paths to the files you wish to work with before signing, encrypting, decrypting, and verifying.
```php

/**
 *  The input and output files could be ".cms". Not just ".txt"
 *  Do not use "file://" just "./folder/file.txt" for example.
 */


// Set the input filename for the data to be signed
$gobuy->setInputFilename("../../CMS/data_5.txt");

// Set the output filename where the CMS signed data will be saved
$gobuy->setCMSOutputFilename("./gobuy_cypher/signed_data.cms");

// Set the path to the sender's certificate
$gobuy->setSenderCertPath("../../alice/certificate.pem");

// Set the path to the sender's private key
$gobuy->setSenderPrivateKey("../../alice/private_key.pem", "12345");

// Or
// Set the password for the sender's private key, then call "setSenderPrivateKey" with only first argument.
$gobuy->setPrivateKeyPassword("12345");

// Optional: Set email headers for the S/MIME message
// Below are optional
$gobuy->setCMSEncoding( OPENSSL_ENCODING_SMIME ); 
$gobuy->setCMSCipherAlgo( OPENSSL_CIPHER_AES_128_CBC );

$gobuy->setHeader([
    "From" => "sender@example.com",
    "To" => "recipient@example.com",
    "Subject" => "Signed Data"
]);


```
Optional: in case you wish to set up a chain of trust. That is, to generate an intermediate certificate for the `$untrusted_certificates_filename`. This is typically done when you want to provide additional certificates that may be needed to complete the chain of trust during the verification process but are not inherently trusted by the system.
```php

// 
list($intermediateCert, $intermediatCertPath, $intermediatePrivateKey ) = $gobuy->generateIntermediateCert( "../../alice_cred/private_key.pem" );

// Now the end entity's certificate can be created. End entity is also the sender. The sender needs to submit a Certificate Signing Request (CSR) for a certificate to be issued to them.
$days = 365; // How long the certificate will be valid. You can increase this further
$serial = rand(); // Just any random number, for example.
list( $endEntityCert ) = $gobuy->signEndEntityCert( "../../alice_cred/csr.pem", 
                                $intermediatCertPath, $intermediatePrivateKey, 
                                  $days, $serial );

// set $untrusted_certificates_filename. This is needed to verify the sender's 
$gobuy->setUntrustedCertificatesFilename( $intermediateCertPath );

```
Where `$intermediateCert` is the certificate content from file, and `$intermediateCertPath` is the path to the certificate content. `generateCSR` takes the path to the sender's private key. `setUntrustedCertificatesFilename` sets `$untrusted_certificates_filename`. Use carefully.

The above chain of trust can be skipped, where the user goes straight to the signing stage as shown below:

```php

// Sign the data using CMS. You should see output in the specified path.
$gobuy->setUntrustedCertificatesFilename( $intermediatCertPath );
$gobuy->setSenderPrivateKey( "../../alice_cred/private_key.pem", "12345"); // Password protected
$gobuy->cmsSign( $endEntityCert );

```

#### To encrypt a file

```php

// Here you must have invoke the setters like above
if ( $gobuy->cmsSign( $endEntityCert ) ) {
    // This scope means a digital signature was established successfully.

    // Preparing for encryption
    // Set the output filename where the CMS. encrypted data will be saved
    $gobuy->setCMSEncryptedOutput( "./gobuy_cypher/encrypted_data.cms" );
    // Set the path to recipient's certificate.
    $gobuy->setRecipientCertPath( "../../bob_cred/certificate.pem" );
    // Set the path to the recipient's private key.
    $gobuy->setRecipientPrivateKey( "../../bob_cred/private_key.pem", "12345" ); // Password-protected
    
    // Encrypt the signed data using CMS. 
    $gobuy->cmsEncrypt("path/to/signed_data.cms");

} else {
    throw new \Exception( "Signing failed: " . openssl_error_string() );
}


```
It is recommended to compress the file before it takes flight. This will reduce the file size and prevent any latency due to file being too large. If you believe you are working with a small file, you may want to skip this stage of encryption. Below shows how we can effortlessly compress your file after encryption.
```php
// Begin the compression process and create a new ZIP file named "comp.zip".
$gobuy->compressData("comp.zip")
    ->thenAddFileFromString("index.php", "<?php echo 'Hello, world!' ") // Add a file from a string with the name "index.php" containing a simple PHP echo statement.
    ->thenAttach("comp.zip", "pic/dog.jpg")// Attach an image file "dog.jpg" from the "pic" directory to the ZIP archive.
    ->thenAttach("comp.zip", "pic/car.png") // Attach another image file "car.png" from the "pic" directory to the ZIP archive.
    ->thenAttach("comp.zip", "docs/doc.pdf") // Attach a PDF document "doc.pdf" from the "docs" directory to the ZIP archive.
    ->thenAfterCloseZip();  // Finalize the ZIP archive and close it.
```

You may now proceed as follows:
```php

// Begin the compression process and create a new ZIP file named "comp.zip".
$gobuy->compressData("encryption.zip")
    // Attach an image file "dog.jpg" from the "pic" directory to the ZIP archive.
    ->thenAttach("encryption.zip", "encrypted/encrypted_data.cms")
    // Finalize the ZIP archive and close it.
    ->thenAfterCloseZip();


```

```php
// This is the reciever's end, who will now decrypt the file.
// Continuation from above. Ensure to have called all relevant setters here.
if (  $gobuy->cmsEncrypt("path/to/signed_data.cms") ) {

    // Set the output filename where the decrypted data will be saved
    $gobuy->setDecryptionOutput("./gobuy_cypher/decrypted_data.cms");

    // Decrypt the CMS encrypted data
    $gobuy->cmsDecrypt("./gobuy_cypher/encrypted_data.cms");

} else {
    throw new Exception ( "Something went wrong" );
}

```

```php

// Verify the CMS decrypted data. 
if ($gobuy->cmsVerify ( "./gobuy_cypher/decrypted_data.cms", 
                                "./gobuy_cypher/cms_content_data.pem", 
                                "./gobuy_cipher/cms_signature_data.pem" ))
                        {
                            $gobuy->output( "CMS VERIfied", "Verified!!" );
                        } else {
                            $gobuy->output( "CMS Not VERIfied ". openssl_error_string(), "Not Verified!!" );
                            $gobuy->showAnyError();
                        }


// public function cmsVerify( string $decryptedData, string $output,
//                                 string|null $sigfile = null,
//                                 array $caInfo = [],
//                                 string|null $untrustedCertificatesFilename = null,
//                                 string|null $content = null,
//                                 string|null $pk7 = null,
//                                 int $encoding = OPENSSL_ENCODING_SMIME ): bool | int {


```
The second argument of `cmsVerify` shows the original content (the human-readable message) before signature was signed, that is after the signature is detached. The third argument is a file that holds the detached signature.

## Using PKCS7 System

```php

// Set the input filename for the data to be signed using PKCS7
$gobuy->setInputFilename("path/to/data.txt"); // Holds just plain text.

// Set the output filename where the PKCS7 signed data will be saved
$gobuy->setPKCS7SignedOutputFilename("./path/to/signed_data.cms");

// Set the path to the sender's certificate for PKCS7 signing
$gobuy->setSenderCertPath("path/to/sender/certificate.pem");

// Set the path to the sender's private key for PKCS7 signing
$gobuy->setSenderPrivateKeyPath("path/to/sender/private_key.pem");

// Optional: Set email headers for the S/MIME message for PKCS7
$gobuy->setHeader([
    "From" => "sender@example.com",
    "To" => "recipient@example.com",
    "Subject" => "Signed Data"
]);


// Sign the data using PKCS7
if ($gobuy->pkcs7Sign()) {
    // Set the output filename where the PKCS7 encrypted data will be saved
    $gobuy->setPKCS7EncryptedOutputFilename("./path/to/pkcs7_encrypted_data.cms");

    // Set the path to the recipient's certificate for PKCS7 encryption
    $gobuy->setRecipientCertPath("path/to/recipient/certificate.pem");

    // Generate recipient credentials for PKCS7 encryption
    // $gobuy->generateRecipientCredentials();

    // Encrypt the signed data using PKCS7
    if ($gobuy->pkcs7Encrypt()) {
        // Rest of your code
    }
}

// Set the output filename where the PKCS7 decrypted data will be saved
$gobuy->setPKCS7DecryptedOutputFilename("./path/to/pkcs7_decrypted_data.cms");

// Set the path to the recipient's certificate for PKCS7 decryption
$gobuy->setRecipientCertPath("path/to/recipient/certificate.pem");

// Set the path to the recipient's private key for PKCS7 decryption
$gobuy->setRecipientPrivateKey("path/to/recipient/private_key.pem");

// Decrypt the PKCS7 encrypted data
if ($gobuy->pkcs7Decrypt($gobuy->getPKCS7EncryptedOutputFilename())) {
    // Set the output filename where the PKCS7 original message will be saved
    $gobuy->setPKCS7RawDataOutput( "./path/to/data_pkcs7_content." );

    // Set the path where the detached signature will be saved.
    $gobuy->setPKCS7SignatureOutput( "./path/to/data_pkcs7_signature." );

    // Verify the PKCS7 decrypted data
    $gobuy->pkcs7Verify($gobuy->getPKCS7DecryptedOutputFilename());
}

```
```
## Alternatively
In the context of the class you're working with, the methods `generateRecipientCredentials()` and `generateSenderCredentials()` can be designed to simplify the process of generating credentials. When invoked, these methods can internally create a certificate and a private key for the recipient and sender, respectively. This feature is particularly useful if you prefer not to manually create and manage certificate files and private key files on the filesystem.

Here's an example of how to invoke these methods:

```php
      ...

    list( $recipientRawCert, $recipientPrivateKey ) = $gobuy->generateSenderCredentials( $config, $dn, $expiresIn  )
    
    list( $recipientRawCert, $recipientPrivateKey ) = $gobuy->generateRecipientCredentials( $config, $dn, $expiresIn  )
       
    
```
```php 
 //Where 
        $config = array(
            "digest_alg" => "sha512", // Digest algorithm for the certificate signature
            "private_key_bits" => 4096, // Number of bits for the private key
            "private_key_type" => OPENSSL_KEYTYPE_RSA, // Type of private key to create
        )

        $dn = array(
            "countryName" => "AU", // Country name
            "stateOrProvinceName" => "...", // State or province name
            "localityName" => "...", // Locality name
            "organizationName" => "...", // Organization name
            "organizationalUnitName" => "...", // Organizational unit name
            "commonName" => "www.", // Common name, usually the domain name
            "emailAddress" => "..." // Email address
        ),
        $expiresIn = 365

```

When using these methods, you don't need to worry about file paths or handling certificate files directly. The method takes care of generating the necessary credentials and using them in subsequent cryptographic operations. This makes the process more streamlined and user-friendly, especially for those who may not be familiar with the details of certificate and key management.

Here are the definitions for the `generateSenderCredentials` and `generateRecipientCredentials` methods with comments explaining each parameter:

```php
class GoBuyEncryption
{
    // ... (other class properties and methods)

    /**
     * Generates a new certificate and private key for the sender.
     * 
     * @param array $config Configuration options for the private key and certificate.
     * @param array $dn The Distinguished Name to be used in the certificate.
     * @param int $expiresIn The number of days for the certificate to be valid.
     * 
     * @return void
     */
    public function generateSenderCredentials(
        array $config = array(
            "digest_alg" => "sha512", // Digest algorithm for the certificate signature
            "private_key_bits" => 4096, // Number of bits for the private key
            "private_key_type" => OPENSSL_KEYTYPE_RSA, // Type of private key to create
        ),
        $dn = array(
            "countryName" => "AU", // Country name
            "stateOrProvinceName" => "...", // State or province name
            "localityName" => "...", // Locality name
            "organizationName" => "...", // Organization name
            "organizationalUnitName" => "...", // Organizational unit name
            "commonName" => "www.", // Common name, usually the domain name
            "emailAddress" => "..." // Email address
        ),
        int $expiresIn = 365 // Certificate validity period in days
    ) {
        // Logic to generate sender's certificate and private key
        // ...
    }

    /**
     * Generates a new certificate and private key for the recipient.
     * 
     * @param array $config Configuration options for the private key and certificate.
     * @param array $dn The Distinguished Name to be used in the certificate.
     * @param int $expiresIn The number of days for the certificate to be valid.
     * 
     * @return void
     */
    public function generateRecipientCredentials(
        Array $config = array(
            "digest_alg" => "sha512", // Digest algorithm for the certificate signature
            "private_key_bits" => 4096, // Number of bits for the private key
            "private_key_type" => OPENSSL_KEYTYPE_RSA, // Type of private key to create
        ),
        Array $dn = array(
            "countryName" => "...", // Country name
            "stateOrProvinceName" => "...", // State or province name
            "localityName" => "...", // Locality name
            "organizationName" => "...", // Organization name
            "organizationalUnitName" => "... ", // Organizational unit name
            "commonName" => "...", // Common name, usually the domain name
            "emailAddress" => "..." // Email address
        ),
        int $expiresIn = 365 // Certificate validity period in days
    ) {
        // Logic to generate recipient's certificate and private key
        // ...
    }

    // ... (other class properties and methods)
}
```

These methods are designed to be flexible, allowing you to specify different configurations and distinguished names for the sender and recipient. The `$config` array allows you to define the cryptographic parameters for the certificate and private key generation, while the `$dn` array contains the information that will be included in the subject field of the certificate. The `$expiresIn` parameter sets the validity period of the certificate in days. These methods abstract away the complexity of generating and managing cryptographic credentials, making it easier to implement secure communication in your application.

## All Class Properties 

Here's an explanation of the fields in the `GoBuyEncryption` class:


# GoBuyEncryption Class Fields

## Private Fields

- `inputFilename`: Path to the **input file** that contains the data to be encrypted or signed.
- `cmsOutputFilename`: Path to the **output file** where the CMS signed data will be saved.
- `senderCertPath`: Path to the **certificate file** for the sender.
- `senderPrivateKeyPath`: Path to the **private key file** for the sender.
- `extraCertsPath`: Path to **additional certificates** if needed for the CMS operation.
- `privateKeyPassword`: Specifies the **password** for the sender's private key.
- `header`: An associative array representing the **headers** for the CMS operation.
- `cmsFlag`: A bitmask of flags for the **CMS signing** operation.
- `encoding`: The **encoding type** for the CMS signing operation.
- `untrusted_certificates_filename`: Filename of **additional untrusted certificates** for the CMS operation.
- `log`: **Monolog logger** instance for logging messages.
- `senderInnerGenCert`: Path to the **sender's certificate file** generated internally.
- `recipientInnerGenCert`: Path to the **recipient's certificate file** generated internally.
- `senderInnerGenKey`: Path to the **sender's private key file** generated internally.
- `recipientInnerGenKey`: Path to the **recipient's private key file** generated internally.
- `pkcs7Flag`: Flag for **PKCS7 operation mode**.
- `pkcs7Algo`: Algorithm used for **PKCS7 encryption**.
- `errorLogPath`: Path to the **error log file** for CMS signing.
- `pkcs7EncryptedOutputFilename`: Filename for the **PKCS7 encrypted output**.
- `pkcs7DecryptedOutputFilename`: Filename for the **PKCS7 decrypted output**.
- `pkcs7SignedOutputFilename`: Filename for the **PKCS7 signed output**.
- `senderRawCert`: Raw certificate data for the **sender**.
- `recipientRawCert`: Raw certificate data for the **recipient**.
- `senderPrivateKey`: Private key resource for the **sender**.
- `cmsSigned`: Status of **CMS signing**, initially empty.
- `pkcs7Signed`: Status of **PKCS7 signing**, initially empty.
- `senderCertificate`: Certificate data for the **sender**.
- `recipientPrivateKey`: Private key resource for the **recipient**.
- `cmsEncryptedOutPut`: Output for **CMS encrypted data**.
- `recipientCertificate`: Certificate data for the **recipient**.
- `recipientCertPath`: Path to the **recipient's certificate file**.
- `pkcs7EncryptedOutput`: Output for **PKCS7 encrypted data**.
- `decryptedData`: **Decrypted data** after processing.
- `decryptionOutput`: Output filename for **decrypted data**.

## Public Fields

- `decryptedOutput`: Publicly accessible property for **decrypted output**.
- `pkcs7VerifiedOutput`: Output for **PKCS7 verified data**.


Each field is described with its purpose and the type of data it holds. This documentation provides clarity on the role of each field within the `GoBuyEncryption` class, making it easier for developers to understand and work with the class.

## Exception Handling

The CMS Signer throws exceptions if there are issues with file signing. Make sure to handle these exceptions in your application.

## Initial Work

The CMS Signer Library was created to provide developers with an easy-to-use solution for signing files using Cryptographic Message Syntax (CMS). It simplifies the process of ensuring data integrity and authenticity in PHP applications. The initial release includes core signing features, comprehensive error handling, and integration with Monolog for logging.


## Contributing

Contributions are welcome. Please submit pull requests to the repository.

## License

This library is open-sourced under the MIT license. See the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository.

## Author

- Victory J.M. Uzochukwu - Creator and Lead Developer - [codingdrips1on1](https://github.com/codingdrips1on1/GoBuyEncryption/tree/main)

Main Contributors: [GoBuy.cheap](https://www.gobuy.cheap) and  [CodingDrips.eu](https://www.codingdrips.eu) 

## Books for your information.
____________
You may proceed to get a cope [here](https://www.gobuy.cheap)
____________
![Cryptograph - PHP](crypt.png)
![Integrated Web Dev.](web.png)
