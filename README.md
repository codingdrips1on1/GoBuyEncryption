

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
composer require yourvendor/cms-signer
```

## Usage

To use the CMS Signer, you need to include the Composer autoload file and instantiate the `CMSSigner` class:

```php

require 'vendor/autoload.php';

$gobuy->signFile();

```

## Configuration

Before using the CMS Signer, configure the following properties:

- `inputFilename`: Path to the input file to be signed.
- `outputFilename`: Path where the signed data will be stored.
- `certificatePath`: Path to the certificate file.
- `privateKeyPath`: Path to the private key file.
- `extraCertsPath`: Path to additional certificates (if needed).

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

