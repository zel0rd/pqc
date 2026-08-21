import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class VulnerableCrypto {
    public static void main(String[] args) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher aesEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        System.out.println(md5 + " " + sha1 + " " + des + " " + aesEcb + " " + rsa);
    }
}
