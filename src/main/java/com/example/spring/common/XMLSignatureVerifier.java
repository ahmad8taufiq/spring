package com.example.spring.common;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
// import java.security.Key;
import java.security.PublicKey;
// import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
// import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.NodeList;

public class XMLSignatureVerifier {
    // Static block to configure security properties
    private static PublicKey staticPublicKey = null;
    
    public static void setVerificationPublicKey(PublicKey key) {
        staticPublicKey = key;
    }

    static {
        // SOLUTION 3: System property to allow weak algorithms globally
        System.setProperty("org.jcp.xml.dsig.secureValidation", "false");
        
        // SOLUTION 4: Alternative - modify security properties
        // Security.setProperty("jdk.xml.dsig.secureValidationPolicy", 
        //     "disallowAlg http://www.w3.org/2000/09/xmldsig#md5");
    }
    
    /**
     * Verifies the digital signature of an XML document
     * @param xmlContent The XML content as a string
     * @param debugLog Whether to enable debug logging
     * @return SignatureInfo object containing verification results
     * @throws Exception if verification fails
     */
    public static SignatureInfo verify(String xmlContent, boolean debugLog) throws Exception {
        // Parse the XML document
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xmlContent.getBytes()));
        
        return verifyDocument(doc, debugLog);
    }
    
    /**
     * Verifies the digital signature of an XML document from a file
     * @param xmlFile The XML file to verify
     * @param debugLog Whether to enable debug logging
     * @return SignatureInfo object containing verification results
     * @throws Exception if verification fails
     */
    public static SignatureInfo verifyFile(File xmlFile, boolean debugLog) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(xmlFile);
        
        return verifyDocument(doc, debugLog);
    }
    
    /**
     * Main verification method that processes the DOM document
     */
    private static SignatureInfo verifyDocument(Document doc, boolean debugLog) throws Exception {
        // Find the Signature element
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        String xpathExpression = "//*[local-name()='Signature']";
        
        NodeList nodes = (NodeList) xpath.evaluate(xpathExpression, doc, XPathConstants.NODESET);
        
        if (nodes.getLength() == 0) {
            throw new Exception("Signature is missing in the document");
        }
        
        Node signatureNode = nodes.item(0);
        
        // Create a DOMValidateContext with secure validation disabled to allow SHA1
        DOMValidateContext valContext = new DOMValidateContext(new CustomKeySelector(), signatureNode);
        
        // SOLUTION 1: Disable secure validation to allow SHA1 algorithms
        valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        
        // SOLUTION 2: Alternative - set specific policy to allow SHA1
        // valContext.setProperty("org.apache.jcp.xml.dsig.internal.dom.policy", new CustomPolicy());
        
        // Get the XMLSignature factory
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        
        // Unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        
        // Validate the signature
        boolean coreValidity = signature.validate(valContext);
        
        SignatureInfo result = new SignatureInfo();
        result.setCoreValid(coreValidity);
        result.setSignature(signature);
        
        if (debugLog) {
            System.out.println("Signature validation status: " + coreValidity);
            
            if (!coreValidity) {
                System.out.println("Signature failed core validation");
                
                // Check signature value validity
                boolean sv = signature.getSignatureValue().validate(valContext);
                System.out.println("Signature value validation status: " + sv);
                
                // Check each reference
                Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    Reference ref = i.next();
                    boolean refValid = ref.validate(valContext);
                    System.out.println("Reference[" + j + "] validity status: " + refValid + 
                                     ", ref URI: [" + ref.getURI() + "]");
                    
                    if (refValid) {
                        // Calculate and display digest information
                        String calcDigestStr = digestToString(ref.getCalculatedDigestValue());
                        String expectedDigestStr = digestToString(ref.getDigestValue());
                        System.out.println("Calculated Digest: " + calcDigestStr);
                        System.out.println("Expected Digest: " + expectedDigestStr);
                        
                        // Transform and display the referenced data
                        displayTransformedData(ref, valContext);
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * Custom KeySelector that extracts the public key from the signature
     */
    // private static class CustomKeySelector extends KeySelector {
    //     @Override
    //     public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, 
    //                                   AlgorithmMethod method, XMLCryptoContext context) 
    //                                   throws KeySelectorException {
            
    //         if (keyInfo == null) {
    //             throw new KeySelectorException("KeyInfo is null");
    //         }
            
    //         // Look for X509Certificate in KeyInfo
    //         for (Object content : keyInfo.getContent()) {
    //             if (content instanceof X509Data) {
    //                 X509Data x509Data = (X509Data) content;
    //                 for (Object x509Content : x509Data.getContent()) {
    //                     if (x509Content instanceof X509Certificate) {
    //                         final X509Certificate cert = (X509Certificate) x509Content;
    //                         return new KeySelectorResult() {
    //                             @Override
    //                             public Key getKey() {
    //                                 return cert.getPublicKey();
    //                             }
    //                         };
    //                     }
    //                 }
    //             }
    //         }
            
    //         throw new KeySelectorException("No suitable key found");
    //     }
    // }
    private static class CustomKeySelector extends KeySelector {
        @Override
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose,
                                        AlgorithmMethod method, XMLCryptoContext context)
                throws KeySelectorException {
            if (staticPublicKey == null) {
                throw new KeySelectorException("Public key not set");
            }

            return () -> staticPublicKey;
        }
    }
    
    /**
     * Creates a validation context with proper security settings
     */
    private static DOMValidateContext createSecureValidationContext(KeySelector keySelector, Node signatureNode) {
        DOMValidateContext valContext = new DOMValidateContext(keySelector, signatureNode);
        
        // Disable secure validation to allow SHA1 algorithms
        valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        
        // Set additional properties for legacy algorithm support
        try {
            valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        } catch (Exception e) {
            // Ignore if property is not supported
        }
        
        return valContext;
    }
    
    /**
     * Alternative method with custom policy for specific algorithm control
     */
    public static SignatureInfo verifyWithCustomPolicy(String xmlContent, boolean debugLog) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xmlContent.getBytes()));
        
        return verifyDocumentWithCustomPolicy(doc, debugLog);
    }
    
    /**
     * Verification with custom security policy
     */
    private static SignatureInfo verifyDocumentWithCustomPolicy(Document doc, boolean debugLog) throws Exception {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        String xpathExpression = "//*[local-name()='Signature']";
        
        NodeList nodes = (NodeList) xpath.evaluate(xpathExpression, doc, XPathConstants.NODESET);
        
        if (nodes.getLength() == 0) {
            throw new Exception("Signature is missing in the document");
        }
        
        Node signatureNode = nodes.item(0);
        
        // Create validation context with custom policy
        DOMValidateContext valContext = createSecureValidationContext(new CustomKeySelector(), signatureNode);
        
        // Set custom policy that allows SHA1 but blocks MD5
        valContext.setProperty("org.apache.jcp.xml.dsig.internal.dom.policy", 
            "disallowAlg http://www.w3.org/2000/09/xmldsig#md5");
        
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        
        boolean coreValidity = signature.validate(valContext);
        
        SignatureInfo result = new SignatureInfo();
        result.setCoreValid(coreValidity);
        result.setSignature(signature);
        
        if (debugLog) {
            System.out.println("Signature validation status: " + coreValidity);
            logDetailedValidation(signature, valContext);
        }
        
        return result;
    }
    
    /**
     * Helper method for detailed validation logging
     */
    private static void logDetailedValidation(XMLSignature signature, DOMValidateContext valContext) {
        try {
            boolean sv = signature.getSignatureValue().validate(valContext);
            System.out.println("Signature value validation status: " + sv);
            
            Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
            for (int j = 0; i.hasNext(); j++) {
                Reference ref = i.next();
                boolean refValid = ref.validate(valContext);
                System.out.println("Reference[" + j + "] validity status: " + refValid + 
                                 ", ref URI: [" + ref.getURI() + "]");
            }
        } catch (Exception e) {
            System.out.println("Error during detailed validation: " + e.getMessage());
        }
    }
    private static String digestToString(byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Displays transformed data for debugging
     */
    private static void displayTransformedData(Reference ref, DOMValidateContext valContext) {
        try {
            // This is a simplified version - in practice, you'd need to apply
            // the actual transforms specified in the reference
            StringBuilder sb = new StringBuilder();
            InputStream is = ref.getDigestInputStream();
            if (is != null) {
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                is.close();
                System.out.println("Transformed data: [" + sb.toString() + "]");
            }
        } catch (Exception e) {
            System.out.println("Could not display transformed data: " + e.getMessage());
        }
    }
    
    /**
     * Result class to hold signature verification information
     */
    public static class SignatureInfo {
        private boolean coreValid;
        private XMLSignature signature;
        private List<ReferenceInfo> references = new ArrayList<>();
        
        public boolean isCoreValid() {
            return coreValid;
        }
        
        public void setCoreValid(boolean coreValid) {
            this.coreValid = coreValid;
        }
        
        public XMLSignature getSignature() {
            return signature;
        }
        
        public void setSignature(XMLSignature signature) {
            this.signature = signature;
        }
        
        public List<ReferenceInfo> getReferences() {
            return references;
        }
        
        public void addReference(ReferenceInfo refInfo) {
            this.references.add(refInfo);
        }
    }
    
    /**
     * Information about individual references
     */
    public static class ReferenceInfo {
        private String uri;
        private boolean valid;
        private String calculatedDigest;
        private String expectedDigest;
        
        // Constructors, getters, and setters
        public ReferenceInfo(String uri, boolean valid, String calculatedDigest, String expectedDigest) {
            this.uri = uri;
            this.valid = valid;
            this.calculatedDigest = calculatedDigest;
            this.expectedDigest = expectedDigest;
        }
        
        public String getUri() { return uri; }
        public boolean isValid() { return valid; }
        public String getCalculatedDigest() { return calculatedDigest; }
        public String getExpectedDigest() { return expectedDigest; }
    }
}
