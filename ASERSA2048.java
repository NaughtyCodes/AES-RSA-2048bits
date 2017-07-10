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