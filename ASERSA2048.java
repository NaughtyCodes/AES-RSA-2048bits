package lookatjava;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;
//
// Public Key cryptography using the RSA algorithm.
public class ASERSA2048 {
 
  public static void main (String[] args) throws Exception {
    //
    // check args and get plaintext
    if (args.length !=1) {
      System.err.println("Usage: java PublicExample text");
      System.exit(1);
    }
    byte[] plainText = args[0].getBytes("UTF8");
    //
    // generate an RSA key
    System.out.println( "\nStart generating RSA key" );
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair key = keyGen.generateKeyPair();
    System.out.println("private key -> "+Base64.getEncoder().encodeToString(key.getPrivate().getEncoded()));
    System.out.println("public  key -> "+Base64.getEncoder().encodeToString(key.getPublic().getEncoded()));
    
    //------------converting String to private key
    KeyFactory fac = KeyFactory.getInstance("RSA"); 
    PKCS8EncodedKeySpec prKCS8EncodedKeySpec = new PKCS8EncodedKeySpec(
    		Base64.getDecoder().decode( Base64.getEncoder().encodeToString(key.getPrivate().getEncoded()).getBytes() )
    		);
    PrivateKey privateKey = fac.generatePrivate(prKCS8EncodedKeySpec);
  //------------converting String to public key
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
    		Base64.getDecoder().decode( Base64.getEncoder().encodeToString(key.getPublic().getEncoded()).getBytes() )
    		);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
  //---------------------------------------------
    
    System.out.println( "Finish generating RSA key" );
    //
    // get an RSA cipher object and print the provider   
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    System.out.println( "\n" + cipher.getProvider().getInfo() );
    //
    // encrypt the plaintext using the public key
    System.out.println( "\nStart encryption" );
    	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    //cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
    byte[] cipherText = cipher.doFinal(plainText);
    System.out.println( "Finish encryption: " );
    System.out.println( new String(cipherText, "UTF8") );
    //
    // decrypt the ciphertext using the private key
    System.out.println( "\nStart decryption" );
    	cipher.init(Cipher.DECRYPT_MODE,privateKey);
    //cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());
    byte[] newPlainText = cipher.doFinal(cipherText);
    System.out.println( "Finish decryption: " );
    System.out.println( new String(newPlainText, "UTF8") );
  }
}

//-------------------------------------------------------------------------
//sample output
//Start generating RSA key
//private key -> MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCUtmkvFjc1due1F6aMGVVoQSdWzrlv1Oti26ysxE/hfGWt0x1HWoZz1O2dSKHvDB0PkXelJQccbAJaXP1x2uP897MfJPlgmD92DSDn4c3l76WwDfRpFBk/IBUfT8EaR9nj9wTltoKORiTvrgeoeeKRd5N4vJC/+H+Dw7ALnB1MMFnQ+xGwGooMSjkj6T2ifrusZ9xhQTEHbHCtMgT0XVS5cvVEQptVDSA735Fbr+1nvcq++oRFFoDgZ4Zs6wLOSMV7f47jITNlYnyMFPNSAYRmvCwwqsze0tE9eFa2hmEgtRIZ1VpWTWB2fbsHVTA7GKIXgV9p/VE7mQiapVXdfJ6tAgMBAAECggEAXPyuSo4WmWyvN7IBJusUV2seAQ6kLwQw5xC7KRBbboANSCKQ1TQKjFUg+s8WylWFul1YNcAwcRosYnpw04duNZhgvWGuOTMZw2Q0JiowR82QicRABpBVtP4HlxuUgC1bVkr4GfcELZg4slHcYgFMpW7inIUz8YWdnjN3WdsVCrTgvyjhEY5PI3K3YJfYtf4f2Ivw3ikWjFNaifnaFFDg55mMgWtCuH1WHZoZKRMfxZXiSF1kjcU9T5ynmGfjvDnYRa67mPHOvvTEUII1K6zD/FvvtgOHkktDq6PEOCJyq/hvGFLHR11oOx1HC7hmXX1vCD4i0TMc6YDuSVBpXup1wQKBgQDMXgAmI+Qt8AmYpATeHjFC2opO3tRZdbU0IoYU212DRnc/r2w3rG6ahqFDZtc1nTVuzu5u2UPHn0faOUmaS+0Q5VLq0m6Bn8OnJLCJah6c+Z1SeZ+zGG1x2ur9n9OO222xZipe44U29hkgN8FgbY9Ec2ZXWLmbn4snGe/gl3wcMQKBgQC6SMu6YvRBP9SiZyvAJ3v1KG02/ImcnnRH6MtV4XGuxlXitFSfpRhzD45wBVMbGmds3AotxxHRoaqpw9K1oQPvz+XHO3ArxE/Ewocn5LaVO3tFBy3/5PObWfwQ92veNMrEMddmz2dEDgFf8CwHMLxOwZdC0cAp2hBeV+RjZ5mXPQKBgQC3mvApU++JcfE9KIaTA68gL/U4XKuM39p3R1kM3fRKn4E9Px5Lemg3/iJdysQoj9/UeKbwAdQKQUitfvBoZjRLDKyM+Zd8b4u425abLjLotr2nvktC/Pw+4P5j9DZ+Txdi3LXOYDxrn3f9YPoj5upjBgZ5DOZcMV80NvIy5gYD0QKBgQCTNxRJqAn/xsHz1jTtFkcP53LoEYtvCoo6ie6nYBLHXFZjYr+9qms4AwM94/dZY/R4QyyIINokIO8OWoMaprTFwDaGzKJI9EtV46WMEWN5bBhu5M2lfPpHu0VI4z+Ly4yyn/Dqft3NGoRbnSIuTIWEd9liJQEIEhz9cdg79pOawQKBgDYArTqir/gUbB4JcgPWMh3RlUI3MZmoB4OcCdy1O6jS116vCVIOTinxIbqpkz71HqHLNdrYVfkhPEpw43yvLU+0dJOabB1isJvqUQHUd8v0yWYhyyu+VR920wnkPKJAFhpFr9DK7BFqYmQfUic7JnQH0MgkNnIlbdeJX5EcHAb9
//public  key -> MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlLZpLxY3NXbntRemjBlVaEEnVs65b9TrYtusrMRP4XxlrdMdR1qGc9TtnUih7wwdD5F3pSUHHGwCWlz9cdrj/PezHyT5YJg/dg0g5+HN5e+lsA30aRQZPyAVH0/BGkfZ4/cE5baCjkYk764HqHnikXeTeLyQv/h/g8OwC5wdTDBZ0PsRsBqKDEo5I+k9on67rGfcYUExB2xwrTIE9F1UuXL1REKbVQ0gO9+RW6/tZ73KvvqERRaA4GeGbOsCzkjFe3+O4yEzZWJ8jBTzUgGEZrwsMKrM3tLRPXhWtoZhILUSGdVaVk1gdn27B1UwOxiiF4Ffaf1RO5kImqVV3XyerQIDAQAB
//Finish generating RSA key

//SunJCE Provider (implements RSA, DES, Triple DES, AES, Blowfish, ARCFOUR, RC2, PBE, Diffie-Hellman, HMAC)

//Start encryption
//Finish encryption: 
//=?=Q?gL???)I!?E??[??c?u?M-?iR?L6?z??1+laS?e??Y?:??7??%???X?????4???Tx??????I?bL???c?`??T?y?????CO?4??????????t?&??-gl?|B??????dY?R?_?4???????Z:????iIP?]P????<?;x?P?[I<?E%?y<?$?#?z3I%?>???cD?????w??h{?????3%?????

//Start decryption
//Finish decryption: 
//TestText
//-------------------------------------------------------------------------



