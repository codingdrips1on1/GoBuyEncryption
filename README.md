

# CMS Signer Library

The CMS Signer Library is a PHP utility for signing files using Cryptographic Message Syntax (CMS). It provides a simple interface to sign data and ensure its integrity and authenticity.

## Features

- Easy-to-use CMS signing functionality
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

To use the CMS Signer, you need to include the Composer autoload file and instantiate the `CMSSigner` class:

```php

require 'vendor/autoload.php'; 

/**
 *  The input and output files could be ".cms". Not just ".txt"
 *  Do not use "file://" just "./folder/file.txt" for example.
 */

// Setters
$gobuy->setInputFilename('dummy_input.txt');
$gobuy->setOutputFilename('dummy_output.cms');
$gobuy->setCertificatePath('path/to/dummy_certificate.pem');
$gobuy->setPrivateKeyPath('path/to/dummy_private_key.pem');
$gobuy->setExtraCertsPath('path/to/dummy_extra_certs.pem'); // Skipped this
$gobuy->setPrivateKeyPassword('dummyPassword'); // Default is "1234". Change to any other password for stronger encryption.
$gobuy->setHeader(["To" => "recipient@example.com", "Subject" => "Signed Data"]); // Default is an emptry arr: []
$gobuy->setFlag(OPENSSL_CMS_DETACHED); // Default is OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY
$gobuy->setEncoding(OPENSSL_ENCODING_SMIME); // Default is OPENSSL_ENCODING_DER
$gobuy->setUntrustedCertificatesFilename('path/to/dummy_untrusted_certs.pem'); // This can just be null or omitted.
$gobuy->setLog(new Logger('dummy_logger')); // Choose your prefered logger. Skip to use our default standard loger. A log folder will be created for you in your current dir. Check the log file there for info.

// Getters. Output these to check default values.
$inputFilename = $gobuy->getInputFilename();
$outputFilename = $gobuy->getOutputFilename();
$certificatePath = $gobuy->getCertificatePath();
$privateKeyPath = $gobuy->getPrivateKeyPath();
$extraCertsPath = $gobuy->getExtraCertsPath();
$privateKeyPassword = $gobuy->getPrivateKeyPassword();
$header = $gobuy->getHeader();
$flag = $gobuy->getFlag();
$encoding = $gobuy->getEncoding();
$untrustedCertificatesFilename = $gobuy->getUntrustedCertificatesFilename();
$log = $gobuy->getLog();

// Output the values to verify
echo "Input Filename: " . $inputFilename . "\n";
echo "Output Filename: " . $outputFilename . "\n";
// ... and so on for the rest of the properties


// init the above Before signing
$gobuy->signFile(); // Signs the MIME message in the file with a cert and key and output the result to the supplied file.

```

## Configuration

Before using the CMS Signer, configure the following properties:

- `inputFilename`: Path to the input file to be signed. the content of this file is read and signed.
- `outputFilename`: Path where the signed data will be stored.
- `certificatePath`: Path to the certificate (certificate.pem) file.
- `privateKeyPath`: Path to the private key (private_key.pem) file.
- `extraCertsPath`: Path to additional certificates (optional).

## All Class Properties 

### `inputFilename`
- **Type**: `string`
- **Description**: Path to the input file that will be used in the CMS operation.
- **Default Value**: `'data_5.txt'`

### `outputFilename`
- **Type**: `string`
- **Description**: Path to the output file where the signed data will be stored.
- **Default Value**: `'signed_data_6.cms'`

### `certificatePath`
- **Type**: `string`
- **Description**: Path to the certificate file used in the signing process.
- **Default Value**: `'../alice/certificate.pem'`

### `privateKeyPath`
- **Type**: `string`
- **Description**: Path to the private key file used in the signing process.
- **Default Value**: `'../alice/private_key.pem'`

### `extraCertsPath`
- **Type**: `string`
- **Description**: Path to additional certificates, if needed for the CMS operation.
- **Default Value**: `'path/to/extra_certs.pem'`

### `privateKeyPassword`
- **Type**: `string`
- **Description**: Specifies the password for accessing the private key.
- **Default Value**: `'12345'`

### `header`
- **Type**: `array`
- **Description**: An associative array representing the headers for the CMS operation.
- **Default Value**: `[]` (empty array)

### `flag`
- **Type**: `int`
- **Description**: A bitmask of flags that define the behavior of the CMS signing operation.
- **Default Value**: `OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY`

### `encoding`
- **Type**: `int`
- **Description**: The encoding type for the CMS signing operation.
- **Default Value**: `OPENSSL_ENCODING_DER`

### `untrusted_certificates_filename`
- **Type**: `string|null`
- **Description**: The filename of additional untrusted certificates for the CMS operation.
- **Default Value**: `null`

### `log`
- **Type**: `Logger`
- **Description**: Monolog logger instance for logging messages during the CMS operation.


## Logging

The library uses Monolog for logging. Logs are stored in the `./log` directory.

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

