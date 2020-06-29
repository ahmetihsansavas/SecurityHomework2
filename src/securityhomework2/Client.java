/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityhomework2;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import sun.misc.BASE64Encoder;

/**
 *
 * @author ahmetihsan
 */
public class Client implements Runnable {
//Client için gerekli değişkenleri tanımlıyoruz.
    String username;
    public PublicKey mypublickey;
    public PublicKey otherpublickey;
    public PrivateKey pvt;
    public static Socket clientSocket = null;
    public static PrintStream ps = null;
    public static DataInputStream dis = null;
    public static BufferedReader giris = null;
    public static boolean kapaliMi = false;

    public static void main(String[] args) {

        try {     // Bağlantının başarılı şekilde gerçekleşmesi halinde mesaj yazma
            clientSocket = new Socket("localhost", 3333);
            giris = new BufferedReader(new InputStreamReader(System.in));
            ps = new PrintStream(clientSocket.getOutputStream());
            dis = new DataInputStream(clientSocket.getInputStream());
            System.out.println("Baglantı başarılı.");
        } catch (UnknownHostException e) {
            System.err.println(e.getMessage());
        } catch (IOException e) {
            System.err.println("Bağlantı sağlanamadı");
        }

        if (clientSocket != null && ps != null && dis != null) {
            try {

                // Serverdan okuma için Thread, buradan tek kullanıcımız olsaydı thread kullanamdan yapılabilirdi
                new Thread(new Client()).start();

                while (!kapaliMi) {
                    ps.println(giris.readLine().trim());
                }

                ps.close();
                dis.close();
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("IOException:  " + e);
            }
        }
    }
//Client için constructor metodları.
    Client(Socket clientSocket, KeyPair kp) {
        this.clientSocket = clientSocket;
        this.mypublickey = kp.getPublic();
        this.pvt = kp.getPrivate();
    }

    Client() {

    }
//Client run metodu bu sayede client tan bir cevap beklenicek.
    @Override
    public void run() {

        String cevap;
        try {
    
            while ((cevap = dis.readLine()) != null) {
                System.out.println(cevap);
                if (cevap.indexOf("Gule Gule") != -1) {
                    break;
                }
            }
            kapaliMi = true;
        } catch (IOException e) {
            System.err.println("IOException:  " + e);
        }
    }

    public static String encryptWithPublicKey(String iv, String message, PublicKey publicKey) throws Exception {

        PublicKey apiPublicKey = publicKey;
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, apiPublicKey);
        byte[] encVal = rsaCipher.doFinal(message.getBytes());
        String encryptedValue = new BASE64Encoder().encode(encVal);
        return encryptedValue;
    }

    public static String decryptWithPrivateKey(String message, PrivateKey privateKey) throws Exception {
        PrivateKey pKey = privateKey;
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, pKey);
        byte[] decVal = rsaCipher.doFinal(message.getBytes());
        String decryptedValue = new String(decVal);
        return decryptedValue;
    }

    public PublicKey getPublicKey() {

        return mypublickey;
    }

    public void receivePublicKeyFrom(ClientThread client) {

        otherpublickey = client.getPublicKey();
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

}
