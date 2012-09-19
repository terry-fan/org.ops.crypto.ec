package org.ops.crypto.ec;

import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;

import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class ECUtil {
    public static void sign()
    {
        Security.addProvider(new BouncyCastleProvider());

        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime239v3");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyGen.initialize(ecGenSpec, new SecureRandom());
            KeyPair pair = keyGen.generateKeyPair();
            System.out.println( pair.toString() );

            Signature dsa = Signature.getInstance("SHA1withECDSA");
            dsa.initSign(pair.getPrivate());
            
            String str = "Message to sign";
            byte[] strByte = str.getBytes("UTF-8");
            dsa.update(strByte);

            byte[] realSig = dsa.sign();
            System.out.println("Signature: " + Base64.encodeBase64String(realSig));

            Signature dsaVerifier = Signature.getInstance("SHA1withECDSA");
            dsaVerifier.initVerify(pair.getPublic());
            dsaVerifier.update(strByte);
            boolean verified = dsaVerifier.verify(realSig);

            System.out.println("Veried: " + verified);
                        
        }
        catch (Exception e)
        {
            System.out.println( e );
        }    
    }
}
