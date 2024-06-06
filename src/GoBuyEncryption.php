<?php
// Use Composer's autoload to load dependencies
require '../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use PHPUnit\Framework\TestCase;

/**
 * Class CMSSigner
 *
 * Sign files using CMS (Cryptographic Message Syntax).
 */
class CMSSigner
{
    /**
     * @var string Path to the input file.
     */
    private $inputFilename = 'data_5.txt';

    /**
     * @var string Path to the output file (signed data).
     */
    private $outputFilename = 'signed_data_6.cms';

    /**
     * @var string Path to the certificate file.
     */
    private $certificatePath = '../alice/certificate.pem';

    /**
     * @var string Path to the private key file.
     */
    private $privateKeyPath = '../alice/private_key.pem';

    /**
     * @var string Path to additional certificates (if needed).
     */
    private $extraCertsPath = 'path/to/extra_certs.pem';

    /**
     * @var Logger Monolog logger for logging messages.
     */
    private $log;

    /**
     * CMSSigner constructor.
     */
    public function __construct()
    {
        // Set up the logger
        $this->log = new Logger('cms_signing');
        $this->log->pushHandler(new StreamHandler('./log/cms_signing.log', Logger::INFO));

        // Security: Protect sensitive information
        if (!file_exists($this->privateKeyPath)) {
            $this->log->error('Private key file not found.');
            throw new Exception('Private key file not found.');
        }
    }

    /**
     * Sign the file using CMS.
     *
     * @throws Exception If signing fails or private key is invalid.
     */
    public function signFile()
    {
        // Read the private key and protect it with a passphrase if necessary
        $privateKey = openssl_pkey_get_private(file_get_contents($this->privateKeyPath), 'cool');

        // Check if the private key is valid
        if (!$privateKey) {
            $this->log->error('Invalid private key.');
            throw new Exception('Invalid private key.');
        }

        // Sign the file using CMS
        $isSigned = openssl_cms_sign(
            $this->inputFilename,
            $this->outputFilename,
            "file://{$this->certificatePath}",
            $privateKey,
            [],
            OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY,
            OPENSSL_ENCODING_DER,
            null
        );

        // Check if the file was signed successfully
        if (!$isSigned) {
            $this->log->error('Failed to sign the file.');
            throw new Exception('Failed to sign the file.');
        }

        $this->log->info('The file has been successfully signed.');
    }
}

// Usage example:
try {
    $cmsSigner = new CMSSigner();
    $cmsSigner->signFile();
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
