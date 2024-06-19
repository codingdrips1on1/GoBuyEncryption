<?php
// Use Composer's autoload to load dependencies

namespace GoBuy\Encryption;

require '../../vendor/autoload.php';
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use PHPUnit\Framework\TestCase;



trait MyChainOfTrust 
{

    // Configuration for the protected key
protected $configArgs = [
    "digest_alg" => "sha512",
    "private_key_bits" => 4096,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];

protected $config = [
    'digest_alg' => 'sha256',
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
];

// Distinguished Name for the root CA
protected $rootCADN = [
    "countryName" => "US",
    "stateOrProvinceName" => "Massachusetts",
    "localityName" => "Waltham",
    "organizationName" => "GoBuy",
    "organizationalUnitName" => "GoBuy Data Security",
    "commonName" => "gobuy.com",
    "emailAddress" => "security@gobuy.com"
];



/**
 * Generates a new protected key.
 *
 * @param array $configArgs Configuration for generating the protected key.
 * @return resource The protected key resource.
 */
public function generatePrivateKey($configArgs = []) {
    // Generate a new protected key
    $privateKey = openssl_pkey_new($configArgs);
    if (!$privateKey) {
        die('Failed to generate protected key: ' . openssl_error_string());
    }
    return $privateKey;
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


abstract public function output( mixed $str, string $id = "Err: " );
public $zip; 
public function compressData ( string $zipFilePath ): GoBuyEncryption {
    // $filename = 'myFiles.zip';
    if ( !file_exists( $zipFilePath ) )
    {
        exec( "echo '' > ".$zipFilePath );
        fwrite(fopen( $zipFilePath, "wb" ), "" );
        // $this->zip->addFile($zipFilePath, 'new/crs');
    }
    if ($this->zip->open($zipFilePath, ZipArchive::CREATE) === TRUE) {
        // $zip->addFromString('info.txt', 'File content goes here');
        // $this->zip->addFile($zipFilePath, 'new/csr');
        // $zip->close();
        // echo 'ZIP archive created successfully.';
        $this->output( "ZIP archive created successfully.", "Zipped!!" );
    } else {
        $this->output( 'Failed to create ZIP archive.', "Zip Err!" ); 
    }

        return $this;

}

public function thenAfterCloseZip( )
{
    $this->zip->close();
}
public function thenAttach( string $attachment, string $path )
{
    $this->zip->addFile($attachment, $path);
    return $this;
}
public function thenAddFileFromString( string $path, string $fileContent )
{
    $this->zip->addFromString($path, $fileContent);
    return $this;
}


/**
 * Signs a CSR with the CA's certificate and protected key to create an intermediate or end-entity certificate.
 *
 * @param resource|string $csr The CSR resource.
 * @param resource|string $caCert The CA's certificate resource.
 * @param resource|string $caPrivateKey The CA's protected key resource.
 * @param int $days The number of days to certify the certificate for.
 * @param array $configArgs Configuration for generating the certificate.
 * @return string The certificate data.
 */
public function signCSR($csr, $caCert, $caPrivateKey, $days, $configArgs = []) {
    // Sign the CSR with the CA's certificate and protected key
    $csr = file_get_contents( $csr );
    $caCert = file_get_contents( $caCert );
    $caPrivateKey = file_get_contents( $caPrivateKey );
    $cert = openssl_csr_sign($csr, $caCert, $caPrivateKey, $days, $configArgs);
    if (!$cert) {
        die('Failed to sign the CSR: ' . openssl_error_string());
    }

    return $cert;

}

protected function folderExistsOrCreate( string $folderName ): void {
            if ( !is_dir( $folderName ) )
                mkdir( $folderName );
}
    
}

/**
 * Class CMSSigner
 *
 * Sign files using CMS (Cryptographic Message Syntax).
 */
class GoBuyEncryption
{
    use MyChainOfTrust {}
    /**
     * @var string Path to the input file.
     */
    protected $inputFilename = null;

    /**
     * @var string Path to the output file (signed data).
     */
    protected $cmsOutputFilename = 'gobuy_signed_data_6.cms';

    /**
     * @var string Path to additional certificates (if needed).
     */
    protected $extraCertsPath = 'path/to/extra_certs.pem';

    /**
     * @var string Specifies the password for the key.
     */
    protected $privateKeyPassword = '12345';

   /**
     * @var array An associative array representing the headers for the CMS operation.
     */
    protected $header = [];

    /**
     * @var int A bitmask of flags for the CMS signing operation.
     */
    protected $cmsFlag = OPENSSL_CMS_BINARY; // PKCS7_BINARY; // OPENSSL_CMS_BINARY; // OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY
    

    /**
     * @var int The encoding type for the CMS signing operation.
     */
    protected $cmsEncoding = OPENSSL_ENCODING_SMIME; // OPENSSL_ENCODING_SMIME; //OPENSSL_ENCODING_DER;

    /**
     * @var string|null The filename of additional untrusted certificates for the CMS operation.
     */
    protected $untrusted_certificates_filename = null;

    /**
     * @var Logger Monolog logger for logging messages.
     */
    protected $log;
    
     /**
     * @var string Path to the sender's certificate file.
     */
    protected $senderInnerGenCert = 'gobuy_cipher/sender_certificate.pem';

    /**
     * @var string Path to the recipient's certificate file.
     */
    protected $recipientInnerGenCert = 'gobuy_cipher/reciever_certificate.pem';

    /**
     * @var string Path to the sender's protected key file.
     */
    protected $senderInnerGenKey = 'gobuy_cipher/sender_private_key.pem';

    /**
     * @var string Path to the recipient's protected key file.
     */
    protected $recipientInnerGenKey = 'gobuy_cipher/reciever_private_key.pem';

    /**
     * @var int Flag for PKCS7 operation mode.
     */
    protected $pkcs7Flag = PKCS7_BINARY; // | PKCS7_DETACHED; // OPENSSL_CMS_BINARY; // OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY

    /**
     * @var string Algorithm used for PKCS7 encryption.
     */
    protected $pkcs7Algo = OPENSSL_CIPHER_AES_256_CBC;

    /**
     * @var string Path to the error log file for CMS signing.
     */
    protected $errorLogPath = './log/cms_signing.log';

    /**
     * @var string Filename for the PKCS7 encrypted output.
     */
    protected $pkcs7EncryptedOutputFilename;

    /**
     * @var string Filename for the PKCS7 decrypted output.
     */
    protected $pkcs7DecryptedOutputFilename;

    /**
     * @var string Filename for the PKCS7 signed output.
     */
    protected $pkcs7SignedOutputFilename;

    /**
     * @var string Raw certificate data for the sender.
     */
    protected $senderRawCert;

    /**
     * @var string Raw certificate data for the recipient.
     */
    protected $recipientRawCert;

    /**
     * @var resource protected key resource for the sender.
     */
    protected $senderPrivateKey;

    /**
     * @var string Status of CMS signing, initially empty.
     */
    protected $cmsSigned = "Empty";

    /**
     * @var string Status of PKCS7 signing, initially empty.
     */
    protected $pkcs7Signed = "Empty";

    /**
     * @var string Certificate data for the sender.
     */
    protected $senderCertificate;

    /**
     * @var resource protected key resource for the recipient.
     */
    protected $recipientPrivateKey;

    /**
     * @var string Output for CMS encrypted data.
     */
    protected $cmsEncryptedOutPut;

    /**
     * @var string Certificate data for the recipient.
     */
    protected $recipientCertificate;

    /**
     * @var string Path to the recipient's certificate file.
     */
    protected $recipientCertPath = "./gobuy_cipher/recipient_cert.pem";

    /**
     * @var string Output for PKCS7 encrypted data.
     */
    protected $pkcs7EncryptedOutput;

    /**
     * @var string Decrypted data after processing.
     */
    protected $decryptedData;

    /**
     * @var string Output filename for decrypted data.
     */
    protected $decryptionOutput;

    /**
     * @var string Publicly accessible property for decrypted output.
     */
    public $decryptedOutput;

    /**
     * @var string Output for PKCS7 verified data.
     */
    protected $pkcs7RawDataOutput;
    
   

    /**
 * @var string $intermediatePrivateKey
 * Holds the private key of the intermediate certificate authority (CA).
 * This key is used to sign certificates and must be kept secure.
 */
private $intermediatePrivateKey;

/**
 * @var string $caCert
 * Contains the certificate of the certificate authority (CA).
 * This certificate is used to verify the identity of the CA.
 */
private $caCert;

/**
 * @var bool $generateRecipientCredentials
 * Indicates whether to generate credentials for the recipient.
 * When set to true, it means the reciever's credentials were generated internally with external file.
 * 
 */
protected $generateRecipientCredentials = false;

/**
 * @var bool $generateSenderCredentials
 * Indicates whether to generate credentials for the sender.
 * When set to true, it means the sender's credentials were generated internally with external file.
 */
protected $generateSenderCredentials = false;

/**
 * @var int $cmsCipherAlgo
 * Specifies the cipher algorithm to be used for CMS (Cryptographic Message Syntax).
 * OPENSSL_CIPHER_AES_128_CBC represents AES-128 encryption in CBC mode.
 */
protected $cmsCipherAlgo = OPENSSL_CIPHER_AES_128_CBC;

/**
 * @var mixed $pkcs7Encoding
 * Defines the encoding for PKCS#7 data structures.
 *
 */
protected $pkcs7Encoding;

/**
 * @var string $senderPrivateKeyPath
 * Path to the private key file of the sender.
 * This key is used to sign the message or data being sent.
 */
protected $senderPrivateKeyPath;

/**
 * @var string $recipientTempCert
 * Temporary certificate for the recipient.
 * This certificate can be used for one-time or short-term transactions.
 */
private $recipientTempCert;

/**
 * @var string $pkcs7SignatureOutput
 * Stores the output of the PKCS#7 signature process.
 * This is the signature after it has been detached from the encrypted data.
 */
private $pkcs7SignatureOutput;



    /**
     * CMSSigner constructor.
     */
    public function __construct()
    {

        $this->zip = new \ZipArchive();
        // Load the OpenSSL module
        if (!extension_loaded('openssl')) {
            die('OpenSSL extension is not loaded.');
        }


        $this->folderExistsOrCreate( "./CA" );
        $this->folderExistsOrCreate( "./log" );
        $this->folderExistsOrCreate( __DIR__."/gobuy_cipher" );
       

        // Set up the logger
        $this->log = new Logger('cms_signing');
        $this->log->pushHandler(new StreamHandler( $this->errorLogPath, Logger::INFO));

        $this->root = explode( "vendor", dirname( __FILE__ ) );
        $this->root = $this->root[0];
        // Security: Protect sensitive information
        // if (!file_exists($this->senderPrivateKeyPath)) {
        //     $this->log->error('protected key file not found.');
        //     throw new Exception('protected key file not found.');
        // }
    }

    private $root;
    public function getRoot()
    {
        return $this->root;
    }
    public function init(  ): void {
        $this->zip = new \ZipArchive();
        // Load the OpenSSL module
        if (!extension_loaded('openssl')) {
            die('OpenSSL extension is not loaded.');
        }

        $this->root = explode( "vendor", dirname( __FILE__ ) );
        $this->root = $this->root[0];

        $this->folderExistsOrCreate( $this->root."app/CA" );
        $this->folderExistsOrCreate( $this->root."app/log" );
        $this->folderExistsOrCreate( $this->root."app/gobuy_cipher" );
       

        // Set up the logger
        $this->log = new Logger('cms_signing');
        $this->log->pushHandler(new StreamHandler( $this->errorLogPath, Logger::INFO));
    }

    // Set log file path
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
          $this->generateSenderCredentials = false;
      }
  
      // Set sender's Certificate contents
      public function setSenderRawCert($senderRawCert)
      {
          $this->senderRawCert = $senderRawCert;
      }

      // Get sender's certificate contents
      public function getSenderRawCert(): string
      {
          return $this->senderRawCert;
        }
     
    // Set raw data output for PKCS7 during verification
    public function setPKCS7RawDataOutput ( string $pkcs7RawDataOutput ) {
                $this->pkcs7RawDataOutput = $pkcs7RawDataOutput;
    }
    // Get the output
    public function getPKCS7RawDataOutput (  ) {
        return $this->pkcs7RawDataOutput;
    }

    // Set the signature during verification
    public function setPKCS7SignatureOutput ( string $pkcs7SignatureOutput ) {
                $this->pkcs7SignatureOutput = $pkcs7SignatureOutput;
    }

    // Get it
    public function getPKCS7SignatureOutput (  ) {
        return $this->pkcs7SignatureOutput;
    }

    public function getPKCS7EncryptedOutput () {
        return $this->pkcs7EncryptedOutput;
    }
    public function setDecryptionOutput ( string $decryptionOutput ) {
        $this->decryptionOutput = $decryptionOutput;
    }

    // Set the data that has been decrypted.
    public function setDecryptedData ( string $decryptedData ) {
            $this->decryptedData = $decryptedData;
    }
    
    // Get it.
    public function getDecryptedData ( ) {
           return  $this->decryptedData;
    }


    public function setRecipientCertPath ( string $recipientCertPath ) {
        $this->recipientCertPath = $recipientCertPath;
        $this->recipientCertificate = $recipientCertPath;
        $this->generateRecipientCredentials = false;
        $this->recipientTempCert = file_get_contents( $recipientCertPath );
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
      public function setSenderPrivateKey(string $senderPrivateKey, string $password = "12345")
      {

        //   $this->privateKeyPassword = $password;
          $this->senderPrivateKey = openssl_pkey_get_private(file_get_contents($senderPrivateKey),
                 $password );

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
      public function getCMSEncoding()
      {
          return $this->cmsEncoding;
      }

       // Setter for encoding
    public function setCMSEncoding($cmsEncoding)
    {
        $this->cmsEncoding = $cmsEncoding;
    }
 
    // Getter for encoding
    public function getPKCS7Encoding()
    {
        return $this->pkcs7Encoding;
    }

       // Setter for encoding
    public function setPKCS7Encoding($pkcs7Encoding)
    {
        $this->pkcs7Encoding = $pkcs7Encoding;
    }


      // Getter for encoding
      public function getCMSCipherAlgo()
      {
          return $this->cmsCipherAlgo;
      }

       // Setter for encoding
    public function setCMSCipherAlgo($algo)
    {
        $this->cmsCipherAlgo = $algo;
    }
    protected $pkcs7CipherAlgo;
      // Getter for encoding
      public function getPKCS7CipherAlgo()
      {
          return $this->pkcs7CipherAlgo;
      }

       // Setter for encoding
    public function setPKCS7CipherAlgo($algo)
    {
        $this->pkcs7CipherAlgo = $algo;
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
    public function setRecipientPrivateKey(string $recipientPrivateKey, string $password = "12345")
    {
        $this->recipientPrivateKey = openssl_pkey_get_private(file_get_contents($recipientPrivateKey),
                 $password );
    }


   
        /**
     * Generates sender's protected key and certificate.
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

        // Generate a new protected (and public) key pair
        $this->generateSenderCredentials = true;
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $senderPrivateKey);

        $senderPrivateKey = openssl_pkey_get_private($senderPrivateKey, $this->privateKeyPassword );

        // Generate a self-signed certificate
       
        $senderCertificate = openssl_csr_new($dn, $res);
        $senderCertificate = openssl_csr_sign($senderCertificate, null, $res, $expiresIn );

        openssl_x509_export( $senderCertificate, $this->senderRawCert );
        file_put_contents( $this->senderInnerGenCert, $this->senderRawCert );
        openssl_pkey_export_to_file( $senderPrivateKey, $this->senderInnerGenKey );
        $this->senderPrivateKeyPath = $this->senderInnerGenKey;
        // $this->senderCertPath = null;

        return [ $this->senderRawCert, $senderPrivateKey ];

    }

    
    // ...
    public function setCMSEncryptedOutput ( string $cmsEncryptedOutPut ) {
        $this->cmsEncryptedOutPut = $cmsEncryptedOutPut;
    }

     /**
     * Generates recipient's protected key and certificate.
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
        
        $this->generateRecipientCredentials = true;
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $recipientPrivateKey);
        // Read the protected key and protect it with a passphrase if necessary
        $recipientPrivateKey = openssl_pkey_get_private($recipientPrivateKey, $this->privateKeyPassword );
        
        $recipientCertificate = openssl_csr_new($dn, $res);
        $recipientCertificate = openssl_csr_sign($recipientCertificate, null, $res, $expiresIn );
 
        openssl_x509_export( $recipientCertificate, $this->recipientRawCert );
        file_put_contents( $this->recipientInnerGenCert, $this->recipientRawCert );
        // file_put_contents( $this->recipientInnerGenKey, $recipientPrivateKey );
        openssl_pkey_export_to_file( $recipientPrivateKey, $this->recipientInnerGenKey );
        $this->recipientCertificate = $this->recipientInnerGenCert;
        $this->recipientPrivateKey = $this->recipientInnerGenKey;
        return [ $this->recipientRawCert, $recipientPrivateKey ];
        
    }


    /**
     * Sign the file using CMS.
     *
     * @throws Exception If signing fails or protected key is invalid.
     */
    public function cmsSign( string $senderCert ): bool
    {
        list( $cert, $pKey ) = $this->processCreds(  );
        
        // Sign the file using CMS
        $isSigned = openssl_cms_sign(
            $this->inputFilename,
            $this->cmsOutputFilename,
            $senderCert,
            $pKey,
            $this->header,
            $this->cmsFlag,
            $this->cmsEncoding,
            $this->untrusted_certificates_filename
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
   
    protected function processCreds( ?string $cert = null, ?string $pKey = null ): array
    {

            if ( 
                    ($this->senderCertificate instanceof OpenSSLAsymmetricKey) || 
                        ($this->senderCertificate instanceof OpenSSLCertificate) 
                )
                {
                    $cert = $this->senderCertificate;
                    // if ( !$this->generateRecipientCredentials )
                    //     $this->recipientCertificate = file_get_contents($this->recipientCertificate);
                } else {
                    $cert = file_get_contents($this->senderCertificate);
                }


            

            if ( 
                    ($this->senderPrivateKey instanceof OpenSSLAsymmetricKey) || 
                        ($this->senderPrivateKey instanceof OpenSSLCertificate) 
                )
                {
                    // $this->output( "UUUPPP" );
                    $pKey = $this->senderPrivateKey;
                } else {
                    // $this->output( "DWNNN" );
                    $pKey = openssl_pkey_get_private( file_get_contents($this->recipientPrivateKey),
                    $this->privateKeyPassword );
                }

                return [ $cert, $pKey ];

    }
   


    
    public function cmsEncrypt ( string $data  ): bool {

        try {

                $cert = null;
                if ( 
                    ($this->recipientCertificate instanceof OpenSSLAsymmetricKey) || 
                        ($this->recipientCertificate instanceof OpenSSLCertificate) 
                )
                {
                    $cert = $this->recipientCertificate;
                } else {
                    $cert = file_get_contents($this->recipientCertificate);
                    // $this->output( $cert, "hash_file" );
                }


                // $this->header[ "hashed_val" ] = hash_file('sha256', $data);   
                if ( !openssl_cms_encrypt(     
                            $data, 
                            $this->cmsEncryptedOutPut,  
                            $cert,   
                            $this->header,
                            $this->cmsFlag,
                            $this->cmsEncoding,
                            $this->cmsCipherAlgo
                        ) 
                    ) {
                        $this->output( openssl_error_string(), "CMS_ENCRYPTION_ERR" );
                    }

                return true;

        } catch ( Exception $e ) {

            echo "Exc: " . $e->getMessage();

        }
        return false;
    }
   

    
    /**
     * Decrypts data for the recipient.
     * @param string $data The encrypted data
     * @return string The decrypted data
     */
    public function cmsDecrypt($data) {
        // $this->output( $data, __LINE__ );

        // list( $cert, $pKey ) = $this->processCreds(  );
        $cert = null;
        if ( 
            ($this->recipientCertificate instanceof OpenSSLAsymmetricKey) || 
                ($this->recipientCertificate instanceof OpenSSLCertificate) 
        )
        {
            $cert = $this->recipientCertificate;
        } else {
            // $this->output( $this->recipientCertificate, "CERT!" );
            $cert = file_get_contents($this->recipientCertificate);
        }
        $pKey = null;
        if ( 
            ($this->recipientPrivateKey instanceof OpenSSLAsymmetricKey) || 
                ($this->recipientPrivateKey instanceof OpenSSLCertificate) 
        )
        {
            $pKey = $this->recipientPrivateKey;
            $this->output( $pKey, "KEY!" );
        } else {
            $pKey = openssl_pkey_get_private( file_get_contents($this->recipientPrivateKey),
                                                $this->privateKeyPassword );
        }

        $this->output( "pKey: ". $this->senderCertificate
                            . "   --- cert: " . $this->recipientCertificate );
        if (!openssl_pkcs7_decrypt($data, $this->decryptionOutput, 
                                                            $cert,
                                                            $pKey ))
        {
            $this->showAnyError();
            throw new \Exception( "Error decrypting: ". openssl_error_string( ) );
        }


        $this->decryptedData = file_get_contents( $this->decryptionOutput );
        return $this->decryptedData;
        

    }

  

    public function cmsVerify( string $decryptedData, string $output,
                                string|null $sigfile = null,
                                array $caInfo = [],
                                string|null $untrustedCertificatesFilename = null,
                                string|null $content = null,
                                string|null $pk7 = null,
                                int $encoding = OPENSSL_ENCODING_SMIME ): bool | int {

        if ( $this->recipientCertPath instanceof OpenSSLAsymmetricKey || 
            $this->recipientCertPath instanceof OpenSSLCertificate 
         )
        {
            throw new \Exception( "For CMSVerify, Certificate must be a string path: 'path/to/cert.pem'. Use setter to set certificate." );
        }

        try {

           echo "RECCC: ".$this->recipientCertificate;


           openssl_cms_verify (
                        $decryptedData, 
                        0, 
                        // PKCS7_NOVERIFY, 
                        $this->endEntityCertPath,
                        [ "CA/ca.crt" ], 
                        $this->untrusted_certificates_filename,
                        $output,
                        $pk7, 
                        $sigfile,
                        $this->cmsEncoding
                    );

                    return true;
            } catch ( \Exception $e ) { 
                    echo "Error: " . $e->getMessage();
            }

         

            return false;

    }




     /**
     * Verifies the signature of the encrypted data.
     *
     * @param string $senderCertificate The path to sender's certificate.
     * @param OpenSSLAsymmetricKey $senderPrivateKey The path to sender'S protected key.
     * @return bool The decrypted and verified data, or null on failure.
     * 
     */
    public function pkcs7Sign( string $endEntityCert ): bool | self {

        list( $cert, $pKey ) = $this->processCreds(  );
      
        // echo $this->senderCertificate . " ---------";

        // Check for errors in loading the certificate and protected key
        if (!$cert ) {
            throw new \Exception('Unable to read certificate.');
        } else if ( !$pKey ) {
            throw new \Exception('Unable to read key.');
        }

        // $this->output( $this->senderPrivateKey, "UNTRUST" );

        openssl_pkcs7_sign(
            $this->inputFilename, 
            $this->pkcs7SignedOutputFilename, 
            $endEntityCert, 
            $pKey, 
            $this->header, 
            $this->pkcs7Flag,
            $this->untrusted_certificates_filename
        );

        $this->pkcs7Signed = file_get_contents( $this->pkcs7SignedOutputFilename );
        $this->log->info('The file has been successfully signed.');

        return true;

    }

    public function pkcs7Encrypt( ): bool {

        $cert = null;
        if ( 
            ($this->recipientCertificate instanceof OpenSSLAsymmetricKey) || 
                ($this->recipientCertificate instanceof OpenSSLCertificate) 
        )
        {
            $cert = $this->recipientCertificate;
        } else {
            $cert = file_get_contents($this->recipientCertificate);
        }
        
        if (!openssl_pkcs7_encrypt(
                    $this->pkcs7SignedOutputFilename,
                    $this->pkcs7EncryptedOutputFilename,  
                    $cert, 
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
        $cert = null;
        if ( 
            ($this->recipientCertificate instanceof OpenSSLAsymmetricKey) || 
            ($this->recipientCertificate instanceof OpenSSLCertificate) 
            )
        {
            $cert = $this->recipientCertificate;
        } else {
            // $this->output( "pkcs_cert" );
            $cert = file_get_contents($this->recipientCertificate);
        }
        $pKey = null;
        if ( 
            ($this->recipientPrivateKey instanceof OpenSSLAsymmetricKey) || 
                ($this->recipientPrivateKey instanceof OpenSSLCertificate) 
        )
        {
            // $this->output( "pkcs_key" );
            $pKey = $this->recipientPrivateKey;
        } else {
            $pKey = openssl_pkey_get_private( file_get_contents($this->recipientPrivateKey),
                                $this->privateKeyPassword );
        }

        if ( !$cert ) {
            throw new \Exception( "Error in recipient Certificate" );
        } else if ( !$pKey ) {
            throw new \Exception( "Error in recipient privtae key" );
        }

        
        if (!openssl_pkcs7_decrypt(
            $data,  
            $this->pkcs7DecryptedOutputFilename, 
            $cert, 
            $pKey
        )) {
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

        $this->output( $decryptedData );
        if (!openssl_pkcs7_verify(
            $decryptedData,  
            $this->pkcs7Flag,
            $this->recipientCertificate,
            [ "CA/ca.crt" ], 
            $this->untrusted_certificates_filename,
            $this->getPKCS7RawDataOutput(), 
            $this->getPKCS7SignatureOutput()
        ) ) 
        {
            $this->showAnyError();
            throw new \Exception( "Error verifying data. See: " . openssl_error_string() ); 
        }

        $this->output( $this->recipientTempCert );
        $this->output( $this->recipientCertificate );
        file_put_contents( $this->recipientCertificate, $this->recipientTempCert );

        return true;
    }


    
// Generate a CSR for the intermediate CA
public function generateIntermediateCert($rootPrivateKey, $dn = [
                                'countryName' => 'US',
                                'stateOrProvinceName' => 'State',
                                'localityName' => 'City',
                                'organizationName' => 'Organization',
                                'organizationalUnitName' => 'Organizational Unit',
                                'commonName' => 'intermediateCA',
                                'emailAddress' => 'email@example.com'
                            ]) {


            // $this->senderPrivateKey = 
            //     openssl_pkey_get_private( file_get_contents($rootPrivateKey),
            //                     $this->privateKeyPassword );
            $this->intermediatePrivateKey = openssl_pkey_new($this->config);
            $csr = openssl_csr_new($dn, $this->intermediatePrivateKey, $this->config);
            openssl_csr_export($csr, $csrOut);
            return $this->generateIntermediateCertificate( $csr, $this->getSenderCertPath() );


            // return $csrOut;
}

// Sign the CSR with the root CA's certificate and protected key to create the intermediate certificate
public function generateIntermediateCertificate($csr, $rootCert, $daysValid = 365) {

                    list( $caCert, $caKey ) = $this->generateCACertAndPrivateKey();
                    $serial = rand(); // Serial number should be unique and random
                    $intermediateCert = openssl_csr_sign(
                        $csr, 
                         $caCert, 
                                    $caKey,
                                 $daysValid, $this->config, $serial );

                    openssl_x509_export($intermediateCert, $intermediateCertOut);
                    file_put_contents( $this->getIntermediateCertPath(), 
                                                $intermediateCertOut );
                    return [$intermediateCertOut, $this->getIntermediateCertPath(), $this->intermediatePrivateKey ];
                    
}

private $intermediateCertPath;
public function setIntermediateCertPath ( string $intermediateCertPath ) {
        $this->intermediateCertPath = $intermediateCertPath;
}
public function getIntermediateCertPath(  ) {
    return $this->intermediateCertPath;
}
private function generateCACertAndPrivateKey (  ): array {

    // Configuration settings for the certificate
    $config = [
        'digest_alg' => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'x509_extensions' => 'v3_ca',
    ];

    // Create a private key
    $privateKey = openssl_pkey_new($config);

    // Generate a CSR (Certificate Signing Request)
    $csr = openssl_csr_new(['commonName' => 'My CA'], $privateKey, $config);

    // Self-sign the CSR to create the CA certificate
    $caCert = openssl_csr_sign($csr, null, $privateKey, 365, $config);

    // Export the CA certificate and private key to files
    openssl_x509_export_to_file($caCert, 'CA/ca.crt');
    openssl_pkey_export_to_file($privateKey, 'CA/ca.key');

    $this->caCert = $caCert;
    return array( $caCert, $privateKey );  

}


public function signEndEntityCert( string $endEntityCSRPath,
                             string $intermediateCertPath, 
                             OpenSSLAsymmetricKey | string $intermediateKeys,
                             int $days = 365, $serial = 123 ): array {

                    //  $serial = rand(); // Serial number should be unique and random
                     $endEntityCert = openssl_csr_sign(
                                    file_get_contents($endEntityCSRPath), 
                                    file_get_contents($intermediateCertPath), 
                                    $intermediateKeys,
                                             $days, $this->config, $serial );                
                    openssl_x509_export($endEntityCert, $endEntityCertOut);
                    file_put_contents( $this->endEntityCertPath, 
                                                $endEntityCert );

                    return [ $endEntityCertOut,  $this->endEntityCertPath ];
}

    public $endEntityCertPath = "../../alice_cred/trust_cert.pem";

    public function output ( mixed $str, string $id = "Err: " ) {
       
            if ( is_string( $str ) ) {
                echo "<hr /><h1>".$id."</h1>".$str. "<hr />";
            } else {
                var_dump( [$str, "VAR_DUMP"] );
            } 
    
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
