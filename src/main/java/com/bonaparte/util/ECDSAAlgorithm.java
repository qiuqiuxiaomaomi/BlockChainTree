package com.bonaparte.util;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECDSAAlgorithm {
    private static String src = "hello berber" ;

    public static void jdkECDSA(){
         // 1.初始化密钥
         try{
                 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
                 keyPairGenerator.initialize(256);
                 KeyPair keyPair = keyPairGenerator.generateKeyPair() ;
                 ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic() ;
                 ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate() ;
                 // 执行签名
                 PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
                 KeyFactory keyFactory = KeyFactory.getInstance("EC") ;
                 PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec) ;
                 Signature signature = Signature.getInstance("SHA1withECDSA");
                 signature.initSign(privateKey);
                 signature.update(src.getBytes());
                 byte []arr = signature.sign();
                 System.out.println("jdk ecdsa sign :"+ HexBin.encode(arr));
                 // 验证签名
                 X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
                 keyFactory = KeyFactory.getInstance("EC");
                 PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
                 signature = Signature.getInstance("SHA1withECDSA");
                 signature.initVerify(publicKey);
                 signature.update(src.getBytes());
                 boolean bool = signature.verify(arr);
                 System.out.println("jdk ecdsa verify:"+bool);
             }catch(Exception e){

             }
     }
}
