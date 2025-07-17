package com.example.spring;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.security.Security;
import java.security.KeyFactory;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.web.bind.annotation.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.CertificateFactory;

import com.example.spring.common.XMLSignatureVerifier;
import com.example.spring.common.XMLSignatureVerifier.SignatureInfo;
import com.example.spring.dto.PaymentRequestDTO;
import com.example.spring.service.PaymentApiService;
import com.example.spring.xades.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;

@RestController
@RequestMapping("/api")
public class UserController {
    @GetMapping("/")
    public Map<String, Object> hello() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Hello, World!");
        response.put("status", "success");
        response.put("data", new HashMap<>()); 
        return response;
    }

    @GetMapping("/sign")
    public Map<String, Object> signXml() {
        Map<String, Object> response = new HashMap<>();
        try {
            // 1. Load dummy XML to sign
            Document doc = loadYourXmlDocument();
            // printDocument(doc);

            // 2. Load key and certificate
            PrivateKey privateKey = loadPrivateKey();
            PublicKey publicKey = loadPublicKey();
            
            X509Certificate certificate = loadCertificate();
            
            // 3. Generate signed XML
            Document signedDoc = XadesBesSigner.sign(doc, certificate, privateKey, false);

            cleanSignatureValuesInDOM(signedDoc);
            
            // 4. Convert signedDoc to string
            String signedXmlString = documentToStringSafe(signedDoc);
            String minifiedXmlString = minifyXml(signedXmlString);

            System.out.println(minifiedXmlString);

            XMLSignatureVerifier.setVerificationPublicKey(publicKey);
            SignatureInfo signatureInfo = XMLSignatureVerifier.verify(minifiedXmlString, true);

            if(signatureInfo.isCoreValid()) {
                PaymentRequestDTO request = new PaymentRequestDTO();
                request.setTraceReference(UUID.randomUUID().toString());
                request.setService("N");
                request.setType("pacs.008.001.08");
                request.setSender("KIRUBNBBFNRT");
                request.setReceiver("NDPXBNBAXIPS");
                request.setDocument(minifiedXmlString);
    
                PaymentApiService paymentApiService = new PaymentApiService();
                String resp = paymentApiService.sendPaymentRequest(request);
                System.out.println(resp);
            }

            response.put("status", true);
            response.put("message", signatureInfo.isCoreValid());
        } catch (Exception e) {
            response.put("status", false);
            response.put("message", e.getMessage());
        }
        return response;
    }

    private Document loadYourXmlDocument() {
        try {
            // Load XML file dari classpath (src/main/resources/sample.xml)
            InputStream is = getClass().getClassLoader().getResourceAsStream("input.xml");

            if (is == null) {
                throw new RuntimeException("sample.xml not found in classpath");
            }

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true); // sangat penting untuk XMLDSig
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(is);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load XML document", e);
        }
    }

    private PrivateKey loadPrivateKey() {
        try {
            // Tambahkan BouncyCastle sebagai Security Provider
            Security.addProvider(new BouncyCastleProvider());

            // Ambil file .pem dari resources
            InputStream is = getClass().getClassLoader().getResourceAsStream("private-key.pem");
            if (is == null) {
                throw new RuntimeException("private-key.pem not found in classpath");
            }

            PemReader pemReader = new PemReader(new InputStreamReader(is));
            PemObject pemObject = pemReader.readPemObject();
            byte[] keyBytes = pemObject.getContent();
            pemReader.close();

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA"); // atau "EC" tergantung jenis key
            return kf.generatePrivate(keySpec);

        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }

    public PublicKey loadPublicKey() {
        try {
            // Tambahkan BouncyCastle sebagai Security Provider (opsional, tergantung jenis key)
            Security.addProvider(new BouncyCastleProvider());

            // Ambil file public key dari resources
            InputStream is = getClass().getClassLoader().getResourceAsStream("public_key_ku_tarus.pem");
            if (is == null) {
                throw new RuntimeException("public-key.pem not found in classpath");
            }

            PemReader pemReader = new PemReader(new InputStreamReader(is));
            PemObject pemObject = pemReader.readPemObject();
            byte[] keyBytes = pemObject.getContent();
            pemReader.close();

            // Buat PublicKey dari X509EncodedKeySpec
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA"); // Ganti ke "EC" jika pakai elliptic curve
            return kf.generatePublic(keySpec);

        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    private X509Certificate loadCertificate() {
        try {
            // Ambil file .pem dari classpath
            InputStream is = getClass().getClassLoader().getResourceAsStream("signer_cert.pem");
            if (is == null) {
                throw new RuntimeException("certificate.pem not found in classpath");
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(is);

        } catch (Exception e) {
            throw new RuntimeException("Failed to load X.509 certificate", e);
        }
    }

    private String documentToStringSafe(Document doc) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        
        // Minimal configuration to avoid issues
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        
        transformer.transform(new DOMSource(doc), new StreamResult(out));
        
        String result = out.toString("UTF-8");
        
        // Clean problematic characters
        result = result.replaceAll("&#13;", "")
                    .replaceAll("&#10;", "")
                    .replaceAll("&#9;", "");
        
        return result;
    }

    private void cleanSignatureValuesInDOM(Document doc) {
        NodeList signatureValues = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignatureValue");
        
        for (int i = 0; i < signatureValues.getLength(); i++) {
            Element sigValue = (Element) signatureValues.item(i);
            String content = sigValue.getTextContent();
            
            // Remove all whitespace (including newlines, spaces, tabs) from the signature value
            String cleanContent = content.replaceAll("\\s+", "");
            sigValue.setTextContent(cleanContent);
        }
    }

    public String minifyXml(String xmlString) {
        return xmlString.replaceAll(">\\s+<", "><")  // Remove whitespace between tags
                        .replaceAll("\\s+", " ")       // Replace multiple spaces with single space
                        .replaceAll(">\\s+", ">")      // Remove spaces after >
                        .replaceAll("\\s+<", "<")      // Remove spaces before <
                        .trim();                       // Remove leading/trailing whitespace
    }
}
