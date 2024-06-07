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
class GoBuyEncryption
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
     * @var string Specifies the password for the key.
     */
    private $privateKeyPassword = '12345';

   /**
     * @var array An associative array representing the headers for the CMS operation.
     */
    private $header = [];

    /**
     * @var int A bitmask of flags for the CMS signing operation.
     */
    private $flag = OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY;

    /**
     * @var int The encoding type for the CMS signing operation.
     */
    private $encoding = OPENSSL_ENCODING_DER;

    /**
     * @var string|null The filename of additional untrusted certificates for the CMS operation.
     */
    private $untrusted_certificates_filename = null;

    /**
     * @var Logger Monolog logger for logging messages.
     */
    private $log;

    /**
     * CMSSigner constructor.
     */
    public function __construct()
    {

        if ( !is_dir( "./log" ) )
            mkdir( "./log" );
        // Set up the logger
        $this->log = new Logger('cms_signing');
        $this->log->pushHandler(new StreamHandler('./log/cms_signing.log', Logger::INFO));

        // Security: Protect sensitive information
        if (!file_exists($this->privateKeyPath)) {
            $this->log->error('Private key file not found.');
            throw new Exception('Private key file not found.');
        }
    }


      // Getter for inputFilename
      public function getInputFilename()
      {
          return $this->inputFilename;
      }
  
      // Setter for inputFilename
      public function setInputFilename($inputFilename)
      {
          $this->inputFilename = $inputFilename;
      }
  
      // Getter for outputFilename
      public function getOutputFilename()
      {
          return $this->outputFilename;
      }
  
      // Setter for outputFilename
      public function setOutputFilename($outputFilename)
      {
          $this->outputFilename = $outputFilename;
      }
  
      // Getter for certificatePath
      public function getCertificatePath()
      {
          return $this->certificatePath;
      }
  
      // Setter for certificatePath
      public function setCertificatePath($certificatePath)
      {
          $this->certificatePath = $certificatePath;
      }
  
      // Getter for privateKeyPath
      public function getPrivateKeyPath()
      {
          return $this->privateKeyPath;
      }
  
      // Setter for privateKeyPath
      public function setPrivateKeyPath($privateKeyPath)
      {
          $this->privateKeyPath = $privateKeyPath;
      }
  
      // Getter for extraCertsPath
      public function getExtraCertsPath()
      {
          return $this->extraCertsPath;
      }
  
      // Setter for extraCertsPath
      public function setExtraCertsPath($extraCertsPath)
      {
          $this->extraCertsPath = $extraCertsPath;
      }
  
      // Getter for privateKeyPassword
      public function getPrivateKeyPassword()
      {
          return $this->privateKeyPassword;
      }
  
      // Setter for privateKeyPassword
      public function setPrivateKeyPassword($privateKeyPassword)
      {
          $this->privateKeyPassword = $privateKeyPassword;
      }
  
      // Getter for header
      public function getHeader()
      {
          return $this->header;
      }
  
      // Setter for header
      public function setHeader(array $header)
      {
          $this->header = $header;
      }
  
      // Getter for flag
      public function getFlag()
      {
          return $this->flag;
      }
  
      // Setter for flag
      public function setFlag($flag)
      {
          $this->flag = $flag;
      }
  
      // Getter for encoding
      public function getEncoding()
      {
          return $this->encoding;
      }

       // Setter for encoding
    public function setEncoding($encoding)
    {
        $this->encoding = $encoding;
    }

    // Getter for untrusted_certificates_filename
    public function getUntrustedCertificatesFilename()
    {
        return $this->untrusted_certificates_filename;
    }

    // Setter for untrusted_certificates_filename
    public function setUntrustedCertificatesFilename($untrusted_certificates_filename)
    {
        $this->untrusted_certificates_filename = $untrusted_certificates_filename;
    }

    
    // Getter for log
    public function getLog()
    {
        return $this->log;
    }

    // Setter for log
    public function setLog($log)
    {
        $this->log = $log;
    }

    /**
     * Sign the file using CMS.
     *
     * @throws Exception If signing fails or private key is invalid.
     */
    public function signFile(): bool
    {
        // Read the private key and protect it with a passphrase if necessary
        $privateKey = openssl_pkey_get_private(file_get_contents($this->privateKeyPath), $this->privateKeyPassword );

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
            $this->flag, 
            $this->encoding,
            $this->untrusted_certificates_filename
        );

        // Check if the file was signed successfully
        if (!$isSigned) {
            $this->log->error('Failed to sign the file.');
            throw new Exception('Failed to sign the file.');
        }

        $this->log->info('The file has been successfully signed.');

        return true;
    }
}

// Usage example:
try {
    $gobuy = new GoBuyEncryption();
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
    $gobuy->getLog()->error('Error: ' . $e->getMessage());
}
