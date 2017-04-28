/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import sun.misc.BASE64Decoder;
import sun.security.mscapi.SunMSCAPI;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.Map;
import java.util.Map.Entry;

/**
 *
 * @author Administrator
 */
public class SigningProcess {
    static KeyStore ks;
    static SunMSCAPI providerMSCAPI;
    static X509Certificate[] certificateChain = null;
    static Key privateKey = null;
    static String alias;
    static HashMap returnCertificates;

    public static HashMap returnCertificates(){
        HashMap map = new HashMap();
        try {
            providerMSCAPI = new SunMSCAPI();
            Security.addProvider(providerMSCAPI);
            ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
            Field spiField = KeyStore.class.getDeclaredField("keyStoreSpi");
            spiField.setAccessible(true);
            KeyStoreSpi spi = (KeyStoreSpi) spiField.get(ks);
            Field entriesField = spi.getClass().getSuperclass().getDeclaredField("entries");
            entriesField.setAccessible(true);
            Collection entries = (Collection) entriesField.get(spi);
            for (Object entry : entries) {
                alias = (String) invokeGetter(entry, "getAlias");
//                System.out.println("alias :" + alias);
                privateKey = (Key) invokeGetter(entry, "getPrivateKey");
                certificateChain = (X509Certificate[]) invokeGetter(entry, "getCertificateChain");
//                System.out.println(alias + ": " + privateKey + "CERTIFICATES -----------"+Arrays.toString(certificateChain));
            }
            map.put("privateKey", privateKey);
            map.put("certificateChain", certificateChain);
         
        } catch (KeyStoreException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (IOException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (CertificateException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (NoSuchFieldException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (SecurityException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (IllegalArgumentException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (IllegalAccessException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (NoSuchMethodException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (InvocationTargetException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        }
         return map;  
    }
    
    private static Object invokeGetter(Object instance, String methodName)
            throws NoSuchMethodException, IllegalAccessException,
            InvocationTargetException {
        Method getAlias = instance.getClass().getDeclaredMethod(methodName);
        getAlias.setAccessible(true);
        return getAlias.invoke(instance);
    }
    
    public static String sign(String base64,HashMap map){
        String base64string = null; 
        try {
            System.out.println("map :"+map);
        // Getting a set of the entries
     Set set = map.entrySet();
            System.out.println("set :"+set);
     // Get an iterator
     Iterator it = set.iterator();
     // Display elements
     while(it.hasNext()) {
        Entry me = (Entry)it.next();
        String key = (String) me.getKey();
                if("privateKey".equalsIgnoreCase(key)){
                     privateKey = (PrivateKey)me.getValue();
                }
                if("certificateChain".equalsIgnoreCase(key)){
                     certificateChain = (X509Certificate[])me.getValue();
                }
            }
            
            OcspClient ocspClient = new OcspClientBouncyCastle();
            TSAClient tsaClient = null;
            for (int i = 0; i < certificateChain.length; i++) {
                X509Certificate cert = (X509Certificate) certificateChain[i];
                String tsaUrl = CertificateUtil.getTSAURL(cert);
                if (tsaUrl != null) {
                    tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    break;
                }
            }
            List<CrlClient> crlList = new ArrayList<CrlClient>();
            crlList.add(new CrlClientOnline(certificateChain));
            
            String property = System.getProperty("java.io.tmpdir");
             BASE64Decoder decoder = new BASE64Decoder();
             byte[] FileByte = decoder.decodeBuffer(base64);
             writeByteArraysToFile(property+"_unsigned.pdf", FileByte);
            
            
            // Creating the reader and the stamper
            PdfReader reader = new PdfReader(property+"_unsigned.pdf");
            FileOutputStream os = new FileOutputStream(property+"_signed.pdf");
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            // Creating the appearance
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
//            appearance.setReason(reason);
//            appearance.setLocation(location);
            appearance.setAcro6Layers(false);
            appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig1");
            // Creating the signature
            ExternalSignature pks = new PrivateKeySignature((PrivateKey) privateKey, DigestAlgorithms.SHA256, providerMSCAPI.getName());
            ExternalDigest digest = new BouncyCastleDigest();
            MakeSignature.signDetached(appearance, digest, pks, certificateChain, crlList, ocspClient, tsaClient, 0, MakeSignature.CryptoStandard.CMS);
            
            InputStream docStream = new FileInputStream(property+"_signed.pdf");
            byte[] encodeBase64 = Base64.encodeBase64(IOUtils.toByteArray(docStream));
            base64string = new String(encodeBase64);
        } catch (IOException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (DocumentException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        } catch (GeneralSecurityException ex) {
            System.out.println("Exception :"+ex.getLocalizedMessage());
        }
        return base64string;
    }
    
    public static void writeByteArraysToFile(String fileName, byte[] content) throws IOException {
        File file = new File(fileName);
        BufferedOutputStream writer = new BufferedOutputStream(new FileOutputStream(file));
        writer.write(content);
        writer.flush();
        writer.close();
 
    } 

    public static void main(String[] args) {
        returnCertificates = returnCertificates();
        System.out.println("returnCertificates :" + returnCertificates.get("privateKey"));
        String base64 = "JVBERi0xLjcNCiWhs8XXDQoxIDAgb2JqDQo8PC9QYWdlcyAyIDAgUiAvVHlwZS9DYXRhbG9nPj4N\n" +
"CmVuZG9iag0KMiAwIG9iag0KPDwvQ291bnQgMS9LaWRzWyA0IDAgUiBdL1R5cGUvUGFnZXM+Pg0K\n" +
"ZW5kb2JqDQozIDAgb2JqDQo8PC9DcmVhdGlvbkRhdGUoRDoyMDE3MDQyNzEzMTUzNykvQ3JlYXRv\n" +
"cihQREZpdW0pL1Byb2R1Y2VyKFBERml1bSk+Pg0KZW5kb2JqDQo0IDAgb2JqDQo8PC9Db250ZW50\n" +
"cyA1IDAgUiAvQ3JvcEJveFsgMCAwIDU5NSA4NDJdL01lZGlhQm94WyAwIDAgNTk1IDg0Ml0vUGFy\n" +
"ZW50IDIgMCBSIC9SZXNvdXJjZXMgNiAwIFIgL1JvdGF0ZSAwL1R5cGUvUGFnZT4+DQplbmRvYmoN\n" +
"CjUgMCBvYmoNCjw8L0ZpbHRlci9GbGF0ZURlY29kZS9MZW5ndGggMTUzMD4+c3RyZWFtDQpIibRX\n" +
"S2/jNhBGr/4Vc1uqiBW9H8d0tynQ02IroIduD7LEJCpk0RDppPlT/Y2dB2l7nS0KLFoEUPgacuab\n" +
"mW/GP3Sb267LIIXuYZMWcVJAgn8yytI8rqukgrqscZ7k0O03t+9tCYPlYwnYYXP70y8pPNrNNomT\n" +
"JKugGzY0qhroXja/qbsoTeJMjdG2jlNldhqibUpD3GjiWg3RNlNrtK3iCnd7Bx8/3MP9RAuNmrWN\n" +
"fu9+Jh0Lr2MmCmbQtHGbkXJZG+eZKMc6JK3XIaMR6zDiu3/BR7O6fjdr+GBQhyRu1XDc68XBfVTG\n" +
"ucJFWlv3uJmjgqjLZ4Xa8ObnCCZLqieqh+MyPevV9rMsPEwzWZXhyKx7FONV9xRGh5WMb5W2en32\n" +
"L+sow2+4cZ7ZzAS2aZyW0H1gCJPGG9K2mRhiHqIcYYGI79dRgaDxRNbN4uzN5TxK8LvymKyKC9Wz\n" +
"jHPTEm1b9MsjuadRN3ySRQc+IaKzOYq05S0RXkZ4lFWZH54mkbFRosDIvV5RL8GXvcpTYrLFm0XK\n" +
"WzEamR5JUdJUX4i6G5AXdbQtcc9r3dMs9waOorGIWQuIFWHafe+jogiRSSMCEwGE/nCYp6F3k1mg\n" +
"R8MOc+/IiXC0rEam9AjOwLBqCdEe3yqU0zC5OPgsi3PvspTC8BRxjJkEUCvYTh7HRWYjX1rypaWa\n" +
"xXMSQg8Somgc6NkfG/iYW80yDYQXQ5XhEsXwOFm3TrujmGJRPzAYpIPZawsUK1cBJqDUJ1BqUfyw\n" +
"GsyQvQUU3Jtl5hda8h1mmQK9sFqYtua4OM2BXRNGL5N7Ik0HVs9LDcCpYZ96MgBTC4M+V9PyGNFl\n" +
"gt/tvWcfAbJhJFkrUkh9F3V/UPpX/lBcVJj+eAYBlZ3GE4NwV0id0htWtSXfc7e8mkXfoJNfX540\n" +
"elOEPaugEV6YYUm9cJ0KKDCgx8xBI7BIT9G2wUAjr2aKDYzhbiYqyBPGSZmjxPiiCR4OIZ4HAqHA\n" +
"E+JA/DCm/YxihoJOhfmw+oUeccMkYLy2rCu5sQjGpj6006SpROFPmrXr+TtGkk40XjE7ChVzpH3S\n" +
"A69NxHuNOkxyZOHjTiIVk4gEZExRdL7E8wwNEQOPBk8N3yCn9nK5aOJkYsFiVMrK5AcYcBcqL4Rx\n" +
"pd5FmIJVEEMPyPKlnvClBhZ2+vKiIx+yXj0yYIu1jbjoq+nwhiNGs7zDYEXw4akX7iYoiQPgzB+e\n" +
"Gij1LDLHP1EGCZzTtqK0tVdJgPqU35gHxdfyQEJjG4ZkEhFSTYx7jVyotD6hsAUoLy4qzxeVclE/\n" +
"v/SvXByR+JEF4LBOSESDL6ZoiVpXzTNZc/PrVTXHRGov8i7JTvj7ggfMy1RbUUUmoca/MwkTUQXj\n" +
"xVE/iyPEP/U1vZDfi+K/xDb0GWndppfQpgRtjnQ3cTGqEdqe/xOZIgwvyIYp4fEaZdQKEHoogwSO\n" +
"1efLrWufUOvwluXkcS6NtfqzH97inF3hHDRvQ4dEFYNJh6OWbOi5QXF6pNIr7YtsEN5hex1n3yz5\n" +
"fobKLtYu7kOseXBkKwmtTL2jMBgKNPmZwr5MvSqkHvLt2gc3F/ysb3awNGdpiAes9Q7rlVAakfJl\n" +
"G0QlXQTZBmx/qFkJzQxnJ9WkSkmtXoyD2VgspkdNKRy6gbMtLIG2SNvmDbpq29LsnCo+jJ8xDZgQ\n" +
"M/Y2Zh3G9bRgWnCiZGp/QL5CNtxN8+SIiNX/yQzbs5oUvkHLDvnpQfyPSQR3g4xWbss/6X4MLdFK\n" +
"vbA/1zN+5BJ2CJVGgm40L8ts+pG7KoksrKG7U+ELr2D8ZESPQfTUxiCJ7i5Z+hwqeXMR9UQOFE90\n" +
"QYW6YdtEs7CqsSX9dyC/mV1zgbBoGt8+vTfsSYz4gb9OflOcOsEaSfFUOHNPvumpvabxKnksG2D3\n" +
"sjr7kyvLYSmRZSqCPKXKGIQm/0NGjlKnzaPBX3n9tL9p9D6Tm2QR3fdVF4SI4ah9pHAFjl9EXUYg\n" +
"hV0eY680/EukCF0CF2hl3QXtEelReBHnc6uh4Ff67sSBP3abvwcArRiH3QoNCmVuZHN0cmVhbQ0K\n" +
"ZW5kb2JqDQo2IDAgb2JqDQo8PC9Db2xvclNwYWNlPDwvQ3M1IDcgMCBSID4+L0V4dEdTdGF0ZTw8\n" +
"L0dTMSA4IDAgUiA+Pi9Gb250PDwvRjIgOSAwIFIgL1RUMiAxMiAwIFIgL1RUNCAxNCAwIFIgL1RU\n" +
"NiAxNiAwIFIgL1RUOCAxOCAwIFIgPj4vUHJvY1NldFsvUERGL1RleHRdPj4NCmVuZG9iag0KNyAw\n" +
"IG9iag0KWy9DYWxSR0I8PC9HYW1tYVsgMi4yMjIyMSAyLjIyMjIxIDIuMjIyMjFdL01hdHJpeFsg\n" +
"MC40MTI0IDAuMjEyNiAwLjAxOTMgMC4zNTc2IDAuNzE1MTkgMC4xMTkyIDAuMTgwNSAwLjA3MjIg\n" +
"MC45NTA1XS9XaGl0ZVBvaW50WyAwLjk1MDUgMSAxLjA4OV0+Pl0NCmVuZG9iag0KOCAwIG9iag0K\n" +
"PDwvU0EgZmFsc2UvU00gMC4wMi9UUi9JZGVudGl0eS9UeXBlL0V4dEdTdGF0ZT4+DQplbmRvYmoN\n" +
"CjkgMCBvYmoNCjw8L0Jhc2VGb250L1N5bWJvbC9FbmNvZGluZyAxMCAwIFIgL1N1YnR5cGUvVHlw\n" +
"ZTEvVG9Vbmljb2RlIDExIDAgUiAvVHlwZS9Gb250Pj4NCmVuZG9iag0KMTAgMCBvYmoNCjw8L0Rp\n" +
"ZmZlcmVuY2VzWyAxL2J1bGxldF0vVHlwZS9FbmNvZGluZz4+DQplbmRvYmoNCjExIDAgb2JqDQo8\n" +
"PC9GaWx0ZXIvRmxhdGVEZWNvZGUvTGVuZ3RoIDIwOD4+c3RyZWFtDQpIiVSQvQ7CMAyE9z6FRxBD\n" +
"2s5VF1g68CMK7GniVpGIE7np0LcnKQXEEEv25dOdLfbNoSETQFzYqRYD9IY04+gmVggdDoagKEEb\n" +
"FdZuqcpKDyLC7TwGtA31DqoqE9cojoFn2LSz7dxzl29BnFkjGxpgcyvujzhoJ++faJEC5FDXoLHP\n" +
"xP4o/UlajPKKLvNiNXQaRy8VsqQBocqL+l2Q9L/2Ibr+3f6+VmVelnUWiY+W4LTJ11tNzDHWsu6S\n" +
"KGUwhN+LeOeTZXrZS4ABAEPIaT8KDQplbmRzdHJlYW0NCmVuZG9iag0KMTIgMCBvYmoNCjw8L0Jh\n" +
"c2VGb250L0FyaWFsLUJvbGRNVC9FbmNvZGluZy9XaW5BbnNpRW5jb2RpbmcvRmlyc3RDaGFyIDMy\n" +
"L0ZvbnREZXNjcmlwdG9yIDEzIDAgUiAvTGFzdENoYXIgMTE2L1N1YnR5cGUvVHJ1ZVR5cGUvVHlw\n" +
"ZS9Gb250L1dpZHRoc1sgMjc4IDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAg\n" +
"MCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCA3MjIgMCAwIDcyMiAwIDYxMSAwIDAgMCAwIDAgMCAw\n" +
"IDAgMCA2NjcgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCA1NTYgNjExIDU1NiA2MTEg\n" +
"NTU2IDAgMCAwIDI3OCAwIDAgMjc4IDAgMCA2MTEgMCAwIDM4OSA1NTYgMzMzXT4+DQplbmRvYmoN\n" +
"CjEzIDAgb2JqDQo8PC9Bc2NlbnQgOTA1L0NhcEhlaWdodCAwL0Rlc2NlbnQgLTIxMS9GbGFncyAz\n" +
"Mi9Gb250QkJveFsgLTYyOCAtMzc2IDIwMzQgMTA0OF0vRm9udE5hbWUvQXJpYWwtQm9sZE1UL0l0\n" +
"YWxpY0FuZ2xlIDAvU3RlbVYgMTMzL1R5cGUvRm9udERlc2NyaXB0b3I+Pg0KZW5kb2JqDQoxNCAw\n" +
"IG9iag0KPDwvQmFzZUZvbnQvVGltZXNOZXdSb21hblBTTVQvRW5jb2RpbmcvV2luQW5zaUVuY29k\n" +
"aW5nL0ZpcnN0Q2hhciAzMi9Gb250RGVzY3JpcHRvciAxNSAwIFIgL0xhc3RDaGFyIDE3NC9TdWJ0\n" +
"eXBlL1RydWVUeXBlL1R5cGUvRm9udC9XaWR0aHNbIDI1MCAwIDAgMCAwIDAgMCAxODAgMzMzIDMz\n" +
"MyAwIDAgMjUwIDAgMjUwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDcyMiAw\n" +
"IDY2NyA3MjIgMCA1NTYgMCAwIDAgMCAwIDAgMCAwIDAgNTU2IDAgNjY3IDAgNjExIDAgMCA5NDQg\n" +
"MCAwIDAgMCAwIDAgMCAwIDAgNDQ0IDUwMCA0NDQgNTAwIDQ0NCAzMzMgNTAwIDUwMCAyNzggMCAw\n" +
"IDI3OCA3NzggNTAwIDUwMCA1MDAgMCAzMzMgMzg5IDI3OCA1MDAgNTAwIDcyMiAwIDUwMCAwIDAg\n" +
"MCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAw\n" +
"IDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDc2MF0+Pg0KZW5kb2Jq\n" +
"DQoxNSAwIG9iag0KPDwvQXNjZW50IDg5MS9DYXBIZWlnaHQgMC9EZXNjZW50IC0yMTYvRmxhZ3Mg\n" +
"MzQvRm9udEJCb3hbIC01NjggLTMwNyAyMDI4IDEwMDddL0ZvbnROYW1lL1RpbWVzTmV3Um9tYW5Q\n" +
"U01UL0l0YWxpY0FuZ2xlIDAvU3RlbVYgMC9UeXBlL0ZvbnREZXNjcmlwdG9yPj4NCmVuZG9iag0K\n" +
"MTYgMCBvYmoNCjw8L0Jhc2VGb250L0FyaWFsTVQvRW5jb2RpbmcvV2luQW5zaUVuY29kaW5nL0Zp\n" +
"cnN0Q2hhciAzMi9Gb250RGVzY3JpcHRvciAxNyAwIFIgL0xhc3RDaGFyIDMyL1N1YnR5cGUvVHJ1\n" +
"ZVR5cGUvVHlwZS9Gb250L1dpZHRoc1sgMjc4XT4+DQplbmRvYmoNCjE3IDAgb2JqDQo8PC9Bc2Nl\n" +
"bnQgOTA1L0NhcEhlaWdodCAwL0Rlc2NlbnQgLTIxMS9GbGFncyAzMi9Gb250QkJveFsgLTY2NSAt\n" +
"MzI1IDIwMjggMTAzN10vRm9udE5hbWUvQXJpYWxNVC9JdGFsaWNBbmdsZSAwL1N0ZW1WIDAvVHlw\n" +
"ZS9Gb250RGVzY3JpcHRvcj4+DQplbmRvYmoNCjE4IDAgb2JqDQo8PC9CYXNlRm9udC9UaW1lc05l\n" +
"d1JvbWFuUFMtQm9sZEl0YWxpY01UL0VuY29kaW5nL1dpbkFuc2lFbmNvZGluZy9GaXJzdENoYXIg\n" +
"MzIvRm9udERlc2NyaXB0b3IgMTkgMCBSIC9MYXN0Q2hhciAxMjEvU3VidHlwZS9UcnVlVHlwZS9U\n" +
"eXBlL0ZvbnQvV2lkdGhzWyAyNTAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDI1MCAwIDAgMCAwIDAg\n" +
"MCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgNjY3IDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAw\n" +
"IDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgMCAwIDAgNTAwIDAgNDQ0IDAgNDQ0IDAg\n" +
"MCA1NTYgMjc4IDAgMCAyNzggMCA1NTYgNTAwIDUwMCAwIDM4OSAzODkgMjc4IDAgMCA2NjcgNTAw\n" +
"IDQ0NF0+Pg0KZW5kb2JqDQoxOSAwIG9iag0KPDwvQXNjZW50IDg5MS9DYXBIZWlnaHQgMC9EZXNj\n" +
"ZW50IC0yMTYvRmxhZ3MgOTgvRm9udEJCb3hbIC01NDcgLTMwNyAxMjA2IDEwMzJdL0ZvbnROYW1l\n" +
"L1RpbWVzTmV3Um9tYW5QUy1Cb2xkSXRhbGljTVQvSXRhbGljQW5nbGUgLTE1L1N0ZW1WIDEzMy9U\n" +
"eXBlL0ZvbnREZXNjcmlwdG9yPj4NCmVuZG9iag0KeHJlZg0KMCAyMA0KMDAwMDAwMDAwMCA2NTUz\n" +
"NSBmDQowMDAwMDAwMDE3IDAwMDAwIG4NCjAwMDAwMDAwNjYgMDAwMDAgbg0KMDAwMDAwMDEyMiAw\n" +
"MDAwMCBuDQowMDAwMDAwMjA5IDAwMDAwIG4NCjAwMDAwMDAzNDMgMDAwMDAgbg0KMDAwMDAwMTk0\n" +
"NiAwMDAwMCBuDQowMDAwMDAyMTA2IDAwMDAwIG4NCjAwMDAwMDIyNzEgMDAwMDAgbg0KMDAwMDAw\n" +
"MjMzOCAwMDAwMCBuDQowMDAwMDAyNDM2IDAwMDAwIG4NCjAwMDAwMDI0OTcgMDAwMDAgbg0KMDAw\n" +
"MDAwMjc3OCAwMDAwMCBuDQowMDAwMDAzMTM2IDAwMDAwIG4NCjAwMDAwMDMzMDIgMDAwMDAgbg0K\n" +
"MDAwMDAwMzgyMSAwMDAwMCBuDQowMDAwMDAzOTkwIDAwMDAwIG4NCjAwMDAwMDQxNDQgMDAwMDAg\n" +
"bg0KMDAwMDAwNDMwMyAwMDAwMCBuDQowMDAwMDA0NjkxIDAwMDAwIG4NCnRyYWlsZXINCjw8DQov\n" +
"Um9vdCAxIDAgUg0KL0luZm8gMyAwIFINCi9TaXplIDIwL0lEWzwxQzhFMDZCNEQ1OTRCQ0Q5NTYz\n" +
"RDczQkRDMEY0NzA2MD48MUM4RTA2QjRENTk0QkNEOTU2M0Q3M0JEQzBGNDcwNjA+XT4+DQpzdGFy\n" +
"dHhyZWYNCjQ4NzUNCiUlRU9GDQo=";
        String sign = sign(base64, returnCertificates);
        System.out.println("sign :" + sign);
    }

}
