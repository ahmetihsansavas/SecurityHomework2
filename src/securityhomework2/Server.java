/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityhomework2;

import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Random;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author ahmetihsan
 */
public class Server {

    // Server soket
    private static ServerSocket serverSocket = null;
    // Client soket
    private static Socket clientSocket = null;
    // Maximum bağlantı sayısı
    private static final int maxClientSayisi = 10;
    // Her bir client için oluşturlacak Thread dizisi
    private static final ClientThread[] threads = new ClientThread[maxClientSayisi];
    public static Client[] clients = new Client[maxClientSayisi];

    


    
    
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {

        serverSocket = new ServerSocket(3333);
        System.out.println(" " + serverSocket.getLocalPort());

        // Her bir client için ayrı soketler ve threadlerin oluşturulması                  
        while (true) {
            try {

                clientSocket = serverSocket.accept();

                int i = 0;
                for (i = 0; i < maxClientSayisi; i++) {
                    //Her client için RSA public ve private key oluştulur ve client a gönderilir.
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(2048);
                    KeyPair kp = kpg.generateKeyPair();
                    Key pub = kp.getPublic();
                    Key pvt = kp.getPrivate();
                    Client c = new Client(clientSocket, kp);
                    if (threads[i] == null) {
                        //Bos threadler aktif client lara atanır. 
                        (threads[i] = new ClientThread(clientSocket, threads, c)).start();
                        // Server a bağlanan kullanıcılar görüntülenir.
                        System.out.println(i + 1 + ". Client :" + threads[i].name + " " + clientSocket);
                        clients[i] = c;
                        c.username = threads[i].name;;
                        break;
                    }
                }

            } catch (IOException e) {
                System.out.println(e);
            }
        }

    }

}


/*
 * Client soketler için oluşturulmuş Thread sınıfı
 * Her bir Client ile Thread eşleştirilmesi ile Multithread uygulama
 */
class ClientThread extends Thread {

    String name;
    PublicKey mypublickey;
    PublicKey otherpublickey;
    PrivateKey pvt;
    public DataInputStream dis = null;
    public PrintStream ps = null;
    public Socket clientSocket = null;
    public static ClientThread[] threads;
    private int maxClientSayisi;
    public ArrayList<Client> ActiveClient;
    public static Client[] clients;
    int nonce;
    String iv;
    String MacKey;
    String Kc;
    String inputfilename;
    // public Client c;

    public ClientThread(Socket clientSocket, ClientThread[] threads, Client c) {
        this.clientSocket = clientSocket;
        this.threads = threads;
        maxClientSayisi = threads.length;
        this.mypublickey = c.mypublickey;
        this.pvt = c.pvt;
    }

    @Override
    public void run() {
        int maxClientSayisi = this.maxClientSayisi;
        ClientThread[] threads = this.threads;

        try {
 
            dis = new DataInputStream(clientSocket.getInputStream());
            ps = new PrintStream(clientSocket.getOutputStream());
            
            File file = new File("Serverout.txt"); //Bütün mesajlaşmaların yazılacağı text dosyasi
            FileOutputStream fos = new FileOutputStream(file);
            PrintStream ps1 = new PrintStream(fos);
            System.setOut(ps1);

            System.out.println("Nickname Giriniz: ");
            ps.println("Nickname Giriniz: ");
            this.name = dis.readLine().trim();
            ps.println("Merhaba " + name + "! Mesajlasma uygulamasina hosgeldiniz. ");
            System.out.println("Merhaba " + name + "! Mesajlasma uygulamasina hosgeldiniz. ");
  
            for (int i = 0; i < maxClientSayisi; i++) {
                if (threads[i] != null && threads[i] != this) {
                    System.out.println(name + " adli kisi odaya baglandi.");
                    threads[i].ps.println(name + " adli kisi odaya baglandi.");

                }
            }
            while (true) {
                String satir = dis.readLine();
            
                if (satir.startsWith("/quit")) {
                    break;
                }
                for (int i = 0; i < maxClientSayisi; i++) {
                    if (threads[i] != null) {
                        System.out.println("<" + name + ">: " + satir);
                        threads[i].ps.println("<" + name + ">: " + satir);
                    }
                }
                if (satir.startsWith("/dm")) {
                    //Özelden gönderilicek mesajlar için yazılan kısım proje burdan baslıyor...
                    for (int i = 0; i < maxClientSayisi; i++) {
                        if (threads[i].name.equals(name)) {
                            System.out.println(threads[i].name + ":Direct message alicak kullanici adi seciniz.");
                            threads[i].ps.println(threads[i].name + ":Direct message alicak kullanici adi seciniz.");
                            String receiver = dis.readLine();
                            System.out.println(receiver);
                  
                            Handshake(threads[i], threads[i].name, receiver);
                            DirectMessage(threads[i],threads[i].name, receiver);
                            threads[i].ps.println(threads[i].name + ":mesajınız gönderildi.");
                            continue;

                        }
                    }

                }
                if (satir.startsWith("/hs")) {
                    for (int i = 0; i < maxClientSayisi; i++) {
                        if (threads[i].name.equals(name)) {
                            threads[i].ps.println(threads[i].name + ":Handshake yapilacak kullanici adi seciniz.");
                            String receiver = dis.readLine();
                            try {
                                Handshake(threads[i],threads[i].name, receiver);
                                break;
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (Exception ex) {
                                Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
                            }
                            threads[i].ps.println(threads[i].name + ":mesajiniz gönderildi.");
                            continue;

                        }
                    }

                }
            }
            for (int i = 0; i < maxClientSayisi; i++) {
                if (threads[i] != null && threads[i] != this) {
                    threads[i].ps.println(name + " adlı kisi odadan ayrildi.");
                }
            }
            ps.println(name + " Gule Gule!");

            /*
             * Yeni bir Clientın bağlanabilmesi için aktif olan Client null yapılır
             */
 /*for (int j = 0; j < maxClientSayisi; j++) {
                if (threads[j] == this) {
                    threads[j] = null;
                }
            }
             */
            dis.close();
            ps.close();
            clientSocket.close();
        } catch (IOException e) {
        } catch (Exception ex) {
            Logger.getLogger(ClientThread.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void DirectMessage(ClientThread sendert,String sender, String receiver) throws IOException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        ArrayList Mesajlar = new ArrayList();
        ClientThread senderclient = sendert;
        ClientThread receiveclient = null;
        for (int i = 0; i < maxClientSayisi; i++) {
            
            if (threads[i].name.equals(receiver)) {
                //System.out.println("Kullanıcı bulundu...");
                try {
                    dis = new DataInputStream(clientSocket.getInputStream());
                    ps = new PrintStream(clientSocket.getOutputStream());
                } catch (IOException e) {
                }
                String satir = dis.readLine();
               
                if (satir.startsWith("/quit")) {
                    ps.println("direct message dan cikildi");
                    dis.close();
                    ps.close();
                    
                     
                    break;
                }
                for (int z = 0; z < maxClientSayisi; z++) {

                    if (threads[z].name.equals(receiver) && threads[z] != this) {
                        receiveclient=threads[z];   
                     
                        //threads[z].ps.println("<" + sender + ">: " + satir );
                        System.out.println("<" + sender + ">: "+senderclient.AESencrypt(satir, senderclient.iv, senderclient.MacKey));
                        senderclient.ps.println("<" + sender + ">: "+senderclient.AESencrypt(satir, senderclient.iv, senderclient.MacKey));
                        
                        receiveclient.ps.println("<" + sender + ">: " +receiveclient.AESdecrypt(senderclient.AESencrypt(satir, senderclient.iv, senderclient.MacKey),senderclient.iv, senderclient.MacKey));
                        System.out.println("<" + sender + ">: " +receiveclient.AESdecrypt(senderclient.AESencrypt(satir, senderclient.iv, senderclient.MacKey),senderclient.iv, senderclient.MacKey));
                        DirectMessage(senderclient,sender, receiver);
                        
                    }
                }

            } else {

                //System.out.println("kullanıcı adı bulunamadı");
            }

        }

    }

    public void Handshake(ClientThread sendert,String sender, String receiver) throws IOException, NoSuchAlgorithmException, Exception {
        Key spublic;
        Key rpublic;
        ClientThread senderclient = sendert;
        Client Clientsender = null;
        ClientThread receiveclient = null;
        ArrayList Mesajlar = new ArrayList();
        for (int i = 0; i < maxClientSayisi; i++) {

            if (threads[i].name.equals(receiver)) {
                System.out.println("Kullanıcı bulundu.. Handshake islemi basliyor");
     
                
                try {
                    dis = new DataInputStream(clientSocket.getInputStream());
                    ps = new PrintStream(clientSocket.getOutputStream());

                } catch (IOException e) {
                }
                // String satir = dis.readLine();

                for (int z = 0; z < maxClientSayisi; z++) {
                    if (threads[z].name.equals(receiver) && threads[z] != this) {
                        
                        receiveclient = threads[z];
                        //Eger handshake islemi daha önce yapılmıssa yeniden yapılmasına bir daha gerek yok
                        if (receiveclient.otherpublickey != null) {
                            System.out.println("Hali hazırda handshake islemi zaten yapılmıs");
                            break;
                        }
                        else{
                         // Handshake islemi...
                         //Öncelikle iki taraf birb. public Key paylasımı yapılıyor
                        receiveclient.ps.println("<" + sender + ">: " + "Hello " + senderclient.mypublickey.toString());
                        System.out.println("<" + sender + ">: " + "Hello " + senderclient.mypublickey.toString());
                        
                        senderclient.receivePublicKeyFrom(receiveclient);
                        //Nonce olusturma islemi
                        Random r = new Random();
                        int nonce = r.nextInt();
                        receiveclient.nonce=nonce;
                        senderclient.ps.println("<" + receiver + ">: " + threads[z].mypublickey.toString() + " " + nonce);
                        System.out.println("<" + receiver + ">: " + threads[z].mypublickey.toString() + " " + nonce);
                        //Nonce sender taraf. alınıyor
                        receiveclient.receivePublicKeywithNonceFrom(senderclient,receiveclient.nonce);
                        System.out.println("<"+sender +"> :"+"nonce alındı->"+senderclient.nonce);
                        //Sender aldığı nonce u Receiver a sifreleyerek gönderiyor
                       String snonce= Integer.toString(senderclient.nonce);
                       senderclient.ps.println ("ciphertext:"+senderclient.encrypt(snonce, senderclient.otherpublickey));
                        System.out.println("<"+sender +"> :"+"ciphertext:"+senderclient.encrypt(snonce, senderclient.otherpublickey));
                        //Receiver kendi gönderdiği nonce u alıyor
                        receiveclient.ps.println("plaintext:"+receiveclient.decrypt(senderclient.encrypt(snonce, senderclient.otherpublickey), receiveclient.pvt));
                        System.out.println("<" + receiver + ">: "+"plaintext:"+receiveclient.decrypt(senderclient.encrypt(snonce, senderclient.otherpublickey), receiveclient.pvt));
                        
                        String snonce2 = Integer.toString(receiveclient.nonce);
                        String ciphertext = receiveclient.decrypt(senderclient.encrypt(snonce, senderclient.otherpublickey), receiveclient.pvt);
                        //Paylasılan nonce un dogrulugu kontrol ediliyor
                        if (ciphertext.equals(snonce2)) {
                            senderclient.ps.println("<" + receiver + ">: "+"nonce dogru");
                            System.out.println("<" + receiver + ">: "+"nonce dogru");
                            
                            receiveclient.ps.println("<" + sender + ">: "+"nonce dogru");
                            System.out.println("<" + sender + ">: "+"nonce dogru");
                            
                            senderclient.GenerateIv(sendert);
                            System.out.println("<" + sender + ">: "+"keyler olusturuluyor");
                            System.out.println(senderclient.GenerateKey());
                           //User1 için key oluşturma 
                           String ivv= "1234567812345678";
                            senderclient.iv=senderclient.getAlphaNumericString(ivv.length());
                            String key1 = "uxjdNijiyJDyOJ3R";
                           String key =senderclient.getAlphaNumericString(key1.length());
                           senderclient.Kc=key;
                           senderclient.MacKey=senderclient.getAlphaNumericString(key1.length());
                           
                           //user2 için key oluşturma
                           receiveclient.iv=senderclient.getAlphaNumericString(ivv.length());
                           String key2 =senderclient.getAlphaNumericString(key1.length());
                           receiveclient.Kc=key2;
                           receiveclient.MacKey=senderclient.getAlphaNumericString(key1.length());
                         /*  
                            senderclient.ps.println("sss"+senderclient.iv);
                            receiveclient.ps.println(senderclient.AESencrypt("merhaba", senderclient.iv,key));
                            receiveclient.ps.println(senderclient.AESdecrypt(senderclient.AESencrypt("merhaba",senderclient.iv, key),senderclient.iv,key));
                          */
                         
                         senderclient.ps.println("Keyler olusturuldu");
                         System.out.println("<" + sender + ">: "+"Keyler Olusturuldu");
                         
                         receiveclient.ps.println("Keyler geldi");
                         System.out.println("<" + receiver + ">: "+"Keyler geldi");
                        break;
                        }
                        
                        break;
                    }
                }
                
                }
                break;
            } else {

                System.out.println("kullanıcı adı bulunamadı");
            }

        }

    }

    public PublicKey getPublicKey() {

        return mypublickey;
    }
  
    public void receivePublicKeyFrom( ClientThread client) {

        otherpublickey = client.getPublicKey();
    }

     public void receivePublicKeywithNonceFrom( ClientThread client,int nonce) {
        this.nonce = nonce;
        client.nonce=nonce;
        otherpublickey = client.getPublicKey();
    }
    
    
    //RSA kullanarak sifreleme algoritması
    public  String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }
    //RSA kullanarak decrypt etme algoritması
    public  String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }
    //Iv olusturma
    public void GenerateIv(ClientThread client) throws NoSuchAlgorithmException{
       SecureRandom random =  SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        //random iv üretemedğim için iv yi elle atamak zorunda kaldım.
        client.iv= "1234567812345678";
  
    }

    
    //AES key olusturma
    public SecretKey GenerateKey() throws NoSuchAlgorithmException{
    KeyGenerator kgen = KeyGenerator.getInstance("AES");
    kgen.init(128);
    SecretKey skey = kgen.generateKey();
    return skey;
    }
    
    //AES encrypt algoritması
public  String AESencrypt(String value ,String initialvector,String key) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
            IvParameterSpec iv = new IvParameterSpec(initialvector.getBytes("UTF-8")); //init vector türü
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES"); // aes için private key

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //cipher çözümleme tipi
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);// cipher cinsi

      
            byte[] encrpted = cipher.doFinal(value.getBytes()); // şifreleme işlemi 
     


            return DatatypeConverter.printBase64Binary(encrpted);
}
//AES decrypt algoritması
public  String AESdecrypt(String encrypted ,String initialvector,String key) {
    try {
        IvParameterSpec iv = new IvParameterSpec(initialvector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
 
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(encrypted));
 
        return new String(original);
    } catch (Exception ex) {
        ex.printStackTrace();
    }
 
    return null;
}


  // Uzunluğu n kadar olan random string üretme algoritması 
    public String getAlphaNumericString(int n) { 
       
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz"; 
   
        StringBuilder sb = new StringBuilder(n); 
  
        for (int i = 0; i < n; i++) { 
  
            // generate a random number between 
            // 0 to AlphaNumericString variable length 
            int index 
                = (int)(AlphaNumericString.length() 
                        * Math.random()); 
  
            // add Character one by one in end of sb 
            sb.append(AlphaNumericString 
                          .charAt(index)); 
        } 
  
       
        return sb.toString();

}


}