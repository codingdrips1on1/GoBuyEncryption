<?php
// Use Composer's autoload to load dependencies
require '../../vendor/autoload.php';

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
    private $inputFilename = null;

    /**
     * @var string Path to the output file (signed data).
     */
    private $cmsOutputFilename = 'gobuy_signed_data_6.cms';

    /**
     * @var string Path to the certificate file.
     */
    private $senderCertPath = 'gobuy_cypher/sender_certificate.pem';
    
    /**
     * @var string Path to the private key file.
     */
    private $senderPrivateKeyPath = 'gobuy_cypher/sender_private_key.pem';

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
    private $cmsFlag = PKCS7_BINARY; // OPENSSL_CMS_BINARY; // OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY
    

    /**
     * @var int The encoding type for the CMS signing operation.
     */
    private $encoding = OPENSSL_ENCODING_SMIME; //OPENSSL_ENCODING_DER;

    /**
     * @var string|null The filename of additional untrusted certificates for the CMS operation.
     */
    private $untrusted_certificates_filename = null;

    /**
     * @var Logger Monolog logger for logging messages.
     */
    private $log;
    
     /**
     * @var string Path to the sender's certificate file.
     */
    private $senderInnerGenCert = 'gobuy_cypher/sender_certificate.pem';

    /**
     * @var string Path to the recipient's certificate file.
     */
    private $recipientInnerGenCert = 'gobuy_cypher/reciever_certificate.pem';

    /**
     * @var string Path to the sender's private key file.
     */
    private $senderInnerGenKey = 'gobuy_cypher/sender_private_key.pem';

    /**
     * @var string Path to the recipient's private key file.
     */
    private $recipientInnerGenKey = 'gobuy_cypher/reciever_private_key.pem';

    /**
     * @var int Flag for PKCS7 operation mode.
     */
    private $pkcs7Flag = PKCS7_BINARY; // | PKCS7_DETACHED; // OPENSSL_CMS_BINARY; // OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY

    /**
     * @var string Algorithm used for PKCS7 encryption.
     */
    private $pkcs7Algo = OPENSSL_CIPHER_AES_256_CBC;

    /**
     * @var string Path to the error log file for CMS signing.
     */
    private $errorLogPath = './log/cms_signing.log';

    /**
     * @var string Filename for the PKCS7 encrypted output.
     */
    private $pkcs7EncryptedOutputFilename;

    /**
     * @var string Filename for the PKCS7 decrypted output.
     */
    private $pkcs7DecryptedOutputFilename;

    /**
     * @var string Filename for the PKCS7 signed output.
     */
    private $pkcs7SignedOutputFilename;

    /**
     * @var string Raw certificate data for the sender.
     */
    private $senderRawCert;

    /**
     * @var string Raw certificate data for the recipient.
     */
    private $recipientRawCert;

    /**
     * @var resource Private key resource for the sender.
     */
    private $senderPrivateKey;

    /**
     * @var string Status of CMS signing, initially empty.
     */
    private $cmsSigned = "Empty";

    /**
     * @var string Status of PKCS7 signing, initially empty.
     */
    private $pkcs7Signed = "Empty";

    /**
     * @var string Certificate data for the sender.
     */
    private $senderCertificate;

    /**
     * @var resource Private key resource for the recipient.
     */
    private $recipientPrivateKey;

    /**
     * @var string Output for CMS encrypted data.
     */
    private $cmsEncryptedOutPut;

    /**
     * @var string Certificate data for the recipient.
     */
    private $recipientCertificate;

    /**
     * @var string Path to the recipient's certificate file.
     */
    private $recipientCertPath = "./gobuy_cypher/recipient_cert.pem";

    /**
     * @var string Output for PKCS7 encrypted data.
     */
    private $pkcs7EncryptedOutput;

    /**
     * @var string Decrypted data after processing.
     */
    private $decryptedData;

    /**
     * @var string Output filename for decrypted data.
     */
    private $decryptionOutput;

    /**
     * @var string Publicly accessible property for decrypted output.
     */
    public $decryptedOutput;

    /**
     * @var string Output for PKCS7 verified data.
     */
    private $pkcs7VerifiedOutput;
    
   
    /**
     * CMSSigner constructor.
     */
    public function __construct()
    {

        if ( !is_dir( "./log" ) )
            mkdir( "./log" );
        if ( !is_dir( __DIR__."/gobuy_cypher" ) )
            mkdir( __DIR__."/gobuy_cypher" );
        // Set up the logger
        $this->log = new Logger('cms_signing');
        $this->log->pushHandler(new StreamHandler( $this->errorLogPath, Logger::INFO));

        // Security: Protect sensitive information
        // if (!file_exists($this->senderPrivateKeyPath)) {
        //     $this->log->error('Private key file not found.');
        //     throw new Exception('Private key file not found.');
        // }
    }

    public function setLogFilePath ( string $errorLogPath )
    {
            $this->errorLogPath = $errorLogPath;
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
  
      // Getter for cmsOutputFilename
      public function getPKCS7EncryptedOutputFilename()
      {
          return $this->pkcs7EncryptedOutputFilename;
      }
  
      // Setter for cmsOutputFilename
      public function setPKCS7EncryptedOutputFilename( string $pkcs7EncryptedOutputFilename)
      {
          $this->pkcs7EncryptedOutputFilename = $pkcs7EncryptedOutputFilename;
      }
      
      // Getter for cmsOutputFilename
      public function getPKCS7DecryptedOutputFilename()
      {
          return $this->pkcs7DecryptedOutputFilename;
      }
  
      // Setter for cmsOutputFilename
      public function setPKCS7DecryptedOutputFilename( string $pkcs7DecryptedOutputFilename )
      {
          $this->pkcs7DecryptedOutputFilename = $pkcs7DecryptedOutputFilename;
      }
     
      // Getter for cmsOutputFilename
      public function getPKCS7SignedOutputFilename()
      {
          return $this->pkcs7SignedOutputFilename;
      }
  
      // Setter for cmsOutputFilename
      public function setPKCS7SignedOutputFilename( string $pkcs7SignedOutputFilename)
      {
          $this->pkcs7SignedOutputFilename = $pkcs7SignedOutputFilename;
      }
  
      // Getter for cmsOutputFilename
      public function getCMSOutputFilename()
      {
          return $this->cmsOutputFilename;
      }
  
      // Setter for cmsOutputFilename
      public function setCMSOutputFilename( string $cmsOutputFilename)
      {
          $this->cmsOutputFilename = $cmsOutputFilename;
      }
  
      // Getter for senderCertPath
      public function getSenderCertPath()
      {
          return $this->senderCertPath;
      }
  
      // Setter for senderCertPath
      public function setSenderCertPath($senderCertPath)
      {
        // $this->senderCertificate = null;
          $this->senderCertPath = $senderCertPath;
          $this->senderCertificate = $senderCertPath;
      }
  
      public function setSenderRawCert($senderRawCert)
      {
          $this->senderRawCert = $senderRawCert;
      }
      public function getSenderRawCert(): string
      {
          return $this->senderRawCert;
        }
        
        
    public function setPKCS7VerifiedOutput ( string $pkcs7VerifiedOutput ) {
                $this->pkcs7VerifiedOutput = $pkcs7VerifiedOutput;
    }
    public function getPKCS7VerifiedOutput (  ) {
        return $this->pkcs7VerifiedOutput;
    }

    public function getPKCS7EncryptedOutput () {
        return $this->pkcs7EncryptedOutput;
    }
    public function setDecryptionOutput ( string $decryptionOutput ) {
        $this->decryptionOutput = $decryptionOutput;
    }

    public function setDecryptedData ( string $decryptedData ) {
            $this->decryptedData = $decryptedData;
    }
    
    public function getDecryptedData ( ) {
           return  $this->decryptedData;
    }
    public function setRecipientCertPath ( string $recipientCertPath ) {
        $this->recipientCertPath = $recipientCertPath;
        $this->recipientCertificate = $recipientCertPath;
    }
    public function getCMSSigned( string $type = "BIN" ): string {

        if ( $type==="HEX" )
            return bin2hex( $this->cmsSigned );
        if ( $type==="BIN" )
            return $this->cmsSigned;

        return "Wrong type selected";
    }
      // Getter for senderPrivateKey
      public function getSenderPrivateKey()
      {
          return $this->senderPrivateKey;
      }
  
      // Setter for senderPrivateKeyPath
      public function setSenderPrivateKey($senderPrivateKey)
      {
          $this->senderPrivateKey = $senderPrivateKey;
      }

      // Getter for senderPrivateKeyPath
      public function getSenderPrivateKeyPath()
      {
          return $this->senderPrivateKeyPath;
      }
  
      // Setter for senderPrivateKeyPath
      public function setSenderPrivateKeyPath($senderPrivateKeyPath)
      {
          $this->senderPrivateKeyPath = $senderPrivateKeyPath;
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
      public function getCMSFlag()
      {
          return $this->cmsFlag;
      }
  
      // Setter for flag
      public function setCMSFlag($cmsFlag)
      {
          $this->cmsFlag = $cmsFlag;
      }
    
      // Getter for flag
      public function getPKCS77Flag()
      {
          return $this->pkcs7Flag;
      }
  
      // Setter for flag
      public function setPKCS77Flag($pkcs7Flag)
      {
          $this->pkcs7Flag = $pkcs7Flag;
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
    
    // Getter for log
    public function getRecipientPrivateKey(): string 
    {
        return $this->recipientPrivateKey;
    }
    public function getRecipientRawCert(): string 
    {
        return $this->recipientRawCert;
    }
    public function setRecipientRawCert( string $recipientRawCert ) 
    {
        return $this->recipientRawCert = $recipientRawCert;
    }
    // Setter for log
    public function setRecipientPrivateKey(string $recipientPrivateKey)
    {
        $this->recipientPrivateKey = $recipientPrivateKey;
    }


    

        /**
     * Generates sender's private key and certificate.
     */
    public function generateSenderCredentials( array $config = array(
                                                    "digest_alg" => "sha512",
                                                    "private_key_bits" => 4096,
                                                                                                    "private_key_type" => OPENSSL_KEYTYPE_RSA,
                                                    ),  $dn = array(
                                                        "countryName" => "US",
                                                        "stateOrProvinceName" => "Massachusetts",
                                                        "localityName" => "Waltham",
                                                        "organizationName" => "GoBuy",
                                                        "organizationalUnitName" => "GoBuy Data Security",
                                                        "commonName" => "gobuy.com",
                                                        "emailAddress" => "security@gobuy.com"
                                                    ), int $expiresIn = 365 ) {
        // Generate a new private (and public) key pair
        
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $this->senderPrivateKey);

        // Generate a self-signed certificate
       
        $this->senderCertificate = openssl_csr_new($dn, $res);
        $this->senderCertificate = openssl_csr_sign($this->senderCertificate, null, $res, $expiresIn );

        openssl_x509_export( $this->senderCertificate, $this->senderRawCert );
        file_put_contents( $this->senderInnerGenCert, $this->senderRawCert );
        file_put_contents( $this->senderInnerGenKey, $this->senderPrivateKey );
        $this->senderPrivateKeyPath = $this->senderInnerGenKey;
        // $this->senderCertPath = null;

    }

    

    public function setCMSEncryptedOutput ( string $cmsEncryptedOutPut ) {
        $this->cmsEncryptedOutPut = $cmsEncryptedOutPut;
    }

     /**
     * Generates recipient's private key and certificate.
     */
    public function generateRecipientCredentials( Array $config = array(
                                                    "digest_alg" => "sha512",
                                                    "private_key_bits" => 4096,
                                                    "private_key_type" => OPENSSL_KEYTYPE_RSA,
                                                ), Array $dn = array(
                                                    "countryName" => "DE",
                                                    "stateOrProvinceName" => "Baden",
                                                    "localityName" => "Karlsruhe",
                                                    "organizationName" => "Matta",
                                                    "organizationalUnitName" => "Matta Data Security",
                                                    "commonName" => "matta.com",
                                                    "emailAddress" => "security@matta.com"
                                                ), int $expiresIn = 365 ) {
        // Similar steps as generateSenderCredentials() but for the recipient
        // ...
        
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $this->recipientPrivateKey);
        // Read the private key and protect it with a passphrase if necessary
        $this->recipientPrivateKey = openssl_pkey_get_private($this->recipientPrivateKey, $this->privateKeyPassword );
        
        $this->recipientCertificate = openssl_csr_new($dn, $res);
        $this->recipientCertificate = openssl_csr_sign($this->recipientCertificate, null, $res, $expiresIn );
 
        openssl_x509_export( $this->recipientCertificate, $this->recipientRawCert );
        file_put_contents( $this->recipientInnerGenCert, $this->recipientRawCert );
        file_put_contents( $this->recipientInnerGenKey, $this->recipientPrivateKey );
        
    }


    /**
     * Sign the file using CMS.
     *
     * @throws Exception If signing fails or private key is invalid.
     */
    public function cmsSign(): bool
    {
        // Read the private key and protect it with a passphrase if necessary
        // $privateKey = openssl_pkey_get_private(file_get_contents($this->senderPrivateKeyPath), $this->privateKeyPassword );

        // Check if the private key is valid
        // if (!$privateKey) {
        //     $this->log->error('Invalid private key.');
        //     throw new Exception('Invalid private key.');
        // }

        // Sign the file using CMS
        $isSigned = openssl_cms_sign(
            $this->inputFilename,
            $this->cmsOutputFilename,
            $this->senderCertificate,
            $this->senderPrivateKey,
            $this->header,
            $this->cmsFlag
            // PKCS7_BINARY
        );

        // Check if the file was signed successfully
        if (!$isSigned) {
            $this->log->error('Failed to sign the file.');
            throw new Exception('Failed to sign the file.');
        }

        $this->cmsSigned = file_get_contents( $this->cmsOutputFilename );
        $this->log->info('The file has been successfully signed.');

        //$this->cmsEncrypt (  $this->cmsOutputFilename  );        
    
        return true;
    }



    public function cmsEncrypt ( string $data  ) {

        try {

            // echo $this->cmsEncryptedOutPut."<br />";
            if ( !openssl_cms_encrypt(
                    $data, 
                    $this->cmsEncryptedOutPut,  
                    $this->recipientCertificate,   
                    $this->header, 
                    $this->cmsFlag
                ) 
                    ) {
    
                        throw new Exception(  openssl_error_string() );
    
                    }

        } catch ( Exception $e ) {

            echo "Exc: " . $e->getMessage();

        }
    }

   

    
    /**
     * Decrypts data for the recipient.
     * @param string $data The encrypted data
     * @return string The decrypted data
     */
    public function cmsDecrypt($data) {

        openssl_cms_decrypt($data, $this->decryptionOutput, $this->recipientCertificate,
                         $this->recipientPrivateKey );
        $this->decryptedData = file_get_contents( $this->decryptionOutput );
        return $this->decryptedData;

    }

    public function cmsVerify( string $decryptedData ): bool | int {

        if ( $this->recipientCertPath instanceof OpenSSLAsymmetricKey || 
            $this->recipientCertPath instanceof OpenSSLCertificate 
         )
        {
            throw new \Exception( "For CMSVerify, Certificate must be a string path: 'path/to/cert.pem'. Use setter to set certificate." );
        }

        return openssl_cms_verify(
                    $decryptedData, 
                    $this->cmsFlag, 
                    // PKCS7_NOVERIFY, 
                    $this->recipientCertPath,
                    [], 
                    null,
                    null, 
                    'data_cms_verified.txt'
                );
    }




     /**
     * Verifies the signature of the encrypted data.
     *
     * @param string $senderCertificate The path to sender's certificate.
     * @param OpenSSLAsymmetricKey $senderPrivateKey The path to sender'S private key.
     * @return bool The decrypted and verified data, or null on failure.
     * 
     */
    public function pkcs7Sign(): bool | self {
        $privateKey = openssl_pkey_get_private( file_get_contents( $this->senderPrivateKeyPath ), $this->privateKeyPassword );
        
        // echo file_get_contents( $this->senderPrivateKeyPath );
        
        // echo $this->senderPrivateKeyPath . " ---------". $this->senderCertificate;
        if ( !($this->senderCertificate instanceof OpenSSLCertificate) &&
                    !( $this->senderCertificate instanceof OpenSSLAsymmetricKey) )
        {
            $this->senderCertificate = file_get_contents($this->senderCertificate);
        }

        // echo $this->senderCertificate . " ---------";

        // Check for errors in loading the certificate and private key
        if (!$this->senderCertificate ) {
            throw new \Exception('Unable to read certificate.');
        } else if ( !$privateKey ) {
            throw new \Exception('Unable to read key.');
        }

        openssl_pkcs7_sign(
            $this->inputFilename, 
            $this->pkcs7SignedOutputFilename, 
            $this->senderCertificate, 
            $privateKey, 
            $this->header, 
            $this->pkcs7Flag,
            null
        );

        $this->pkcs7Signed = file_get_contents( $this->pkcs7SignedOutputFilename );
        $this->log->info('The file has been successfully signed.');

        return true;

    }

    public function pkcs7Encrypt( ): bool {

        if ( !($this->recipientCertificate instanceof OpenSSLCertificate) &&
                    !( $this->recipientCertificate instanceof OpenSSLAsymmetricKey) )
        {
            $this->recipientCertificate = file_get_contents($this->recipientCertificate);
        }

        
        if (!openssl_pkcs7_encrypt(
                    $this->pkcs7SignedOutputFilename,
                    $this->pkcs7EncryptedOutputFilename,  
                    $this->recipientCertificate, 
                    $this->header, 
                    $this->pkcs7Flag, 
                    $this->pkcs7Algo,
        )) {
            throw new \Exception('Unable to encrypt the data.');
        }

        $this->pkcs7EncryptedOutput = file_get_contents( $this->pkcs7EncryptedOutputFilename );

        return true;
    }

    public function pkcs7Decrypt( string $data ): bool | self {

        if ( !($this->recipientPrivateKey instanceof OpenSSLCertificate) &&
                    !( $this->recipientPrivateKey instanceof OpenSSLAsymmetricKey) )
        {
            $this->recipientPrivateKey = openssl_pkey_get_private( file_get_contents( $this->recipientPrivateKey ), $this->privateKeyPassword );
        }
        
        if ( !($this->recipientCertificate instanceof OpenSSLCertificate) &&
                    !( $this->recipientCertificate instanceof OpenSSLAsymmetricKey) )
        {
            $this->recipientCertificate = file_get_contents($this->recipientCertificate);
        }

        if ( !$this->recipientCertificate ) {
            throw new \Exception( "Error in recipient Certificate" );
        } else if ( !$this->recipientPrivateKey ) {
            throw new \Exception( "Error in recipient privtae key" );
        }

        if (!openssl_pkcs7_decrypt(
            $data,  
            $this->pkcs7DecryptedOutputFilename, 
            $this->recipientCertificate, 
            $this->recipientPrivateKey
        )) {
        
            echo $data. "  Hii: ".$this->pkcs7DecryptedOutputFilename. " Coo: ".$this->recipientCertificate  ;
            $this->showAnyError();
            throw new Exception('Unable to decrypt the data. ' . openssl_error_string() );
        }

        $this->decryptedOutput = file_get_contents( $this->pkcs7DecryptedOutputFilename );
        return true;

    }

   

    /**
     * Verifies the signature of the encrypted data.
     *
     * @param string $decryptedData The decrypted data to be verified.
     * @return bool|int The decrypted and verified data, or null on failure.
     * 
     */
    public function pkcs7Verify( string $decryptedData ): bool | int {
        if ( ($this->senderCertificate instanceof OpenSSLCertificate) ||
                    ( $this->senderCertificate instanceof OpenSSLAsymmetricKey) )
        {
            // $this->senderCertificate = file_get_contents($this->senderCertificate);
            throw new \Exception( "Call 'setSenderCertPath( ... )' first before calling 'pkcs7Verify( ... )'" );
        }
        if (!openssl_pkcs7_verify(
            $decryptedData,  
            PKCS7_NOVERIFY, 
            $this->senderCertificate,
            [], 
            null,
            null, 
            $this->pkcs7VerifiedOutput,
        ) ) throw new \Exception( "Error verifying data. See: " . openssl_error_string() ); 

        return true;
    }


    public function showAnyError ( ) {
        while ( ($e = openssl_error_string())!== false )
        {
            echo $e . "<br />";
        }
    }

}


// Usage example:

try {
    $gobuy = new GoBuyEncryption();
} catch (Exception $e) {
    echo('Error: ' . $e->getMessage());
    throw new Exception('Error: ' . $e->getMessage());
}
