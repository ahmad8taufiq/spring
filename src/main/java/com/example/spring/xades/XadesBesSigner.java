package com.example.spring.xades;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.w3c.dom.Document;
import java.util.Date;
import java.util.TimeZone;

import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.io.ByteArrayOutputStream;

import javax.xml.transform.Transformer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class XadesBesSigner {
    public static Document sign(
        Document doc,
        X509Certificate signerCertificate,
        PrivateKey privateKey,
        boolean debugLog
    ) throws Exception {
        final String xadesNS = "http://uri.etsi.org/01903/v1.3.2#";
        final String signedpropsIdSuffix = "-signedprops";

        XMLSignatureFactory fac = null;
        try {
            fac = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        } catch (Exception e) {
            throw new Exception("Failed to initialize XMLSignatureFactory", e);
        }

        // 1. Prepare KeyInfo
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509IssuerSerial x509is = kif.newX509IssuerSerial(
            signerCertificate.getIssuerX500Principal().toString(),
            signerCertificate.getSerialNumber()
        );
        X509Data x509data = kif.newX509Data(Collections.singletonList(x509is));
        final String keyInfoId = "_" + UUID.randomUUID().toString();
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509data), keyInfoId);

        // 2. Prepare references
        List<Reference> refs = new ArrayList<Reference>();
        Reference ref1 = fac.newReference("#" + keyInfoId, fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod(
        CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)), null, null);
        refs.add(ref1);

        final String signedpropsId = "_" + UUID.randomUUID().toString() + signedpropsIdSuffix;
        Reference ref2 = fac.newReference("#" + signedpropsId, fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod(
        CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)), "http://uri.etsi.org/01903/v1.3.2#SignedProperties", null);
        refs.add(ref2);

        Reference ref3 = fac.newReference(null, fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null)), null, null);
        refs.add(ref3);

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (XMLStructure) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), refs);

        // 3. Create element AppHdr/Sgntr that will contain the <ds:Signature>
        Node appHdr = null;
        NodeList sgntrList = doc.getElementsByTagName("AppHdr");

        if (sgntrList.getLength() != 0) appHdr = sgntrList.item(0);

        if (appHdr == null) throw new Exception("mandatory element AppHdr is missing in the document to be signed");
        Node sgntr = appHdr.appendChild(doc.createElementNS(appHdr.getNamespaceURI(), "Sgntr"));

        DOMSignContext dsc = new DOMSignContext(privateKey, sgntr); 
        if (debugLog) {
            dsc.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE); 
        }
        
        // Configure to avoid line ending issues
        dsc.setProperty("javax.xml.crypto.dsig.internal.dom.DOMSignContext.signatureMethodURI", SignatureMethod.RSA_SHA256);
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "ds");

        // 4. Set up <ds:Object> with <QualifiyingProperties> inside that includes SigningTime
        Element QPElement = doc.createElementNS(xadesNS, "xades:QualifyingProperties"); 
        QPElement.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", xadesNS);
        Element SPElement = doc.createElementNS(xadesNS, "xades:SignedProperties"); 
        SPElement.setAttributeNS(null, "Id", signedpropsId); 
        dsc.setIdAttributeNS(SPElement, null, "Id"); 
        SPElement.setIdAttributeNS(null, "Id", true); 
        QPElement.appendChild(SPElement);
        Element SSPElement = doc.createElementNS(xadesNS, "xades:SignedSignatureProperties"); 
        SPElement.appendChild(SSPElement);
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        df.setTimeZone(TimeZone.getTimeZone("Asia/Singapore"));
        String signingTime = df.format(new Date());
        signingTime = signingTime.replaceAll("[+-]\\d{2}:\\d{2}$", "");
        Element STElement = doc.createElementNS(xadesNS, "xades:SigningTime"); 
        STElement.appendChild(doc.createTextNode(signingTime)); 
        SSPElement.appendChild(STElement);
        DOMStructure qualifPropStruct = new DOMStructure(QPElement);

        List<DOMStructure> xmlObj = new ArrayList<DOMStructure>(); 
        xmlObj.add(qualifPropStruct);
        XMLObject object = fac.newXMLObject(xmlObj, null, null, null);
        List<XMLObject> objects = Collections.singletonList(object);

        // 5. Set up custom URIDereferencer to process Reference without URI
        // This Reference points to element <Document> of MX message
        final NodeList docNodes = doc.getElementsByTagName("Document");
        final Node docNode = docNodes.item(0);
        
        // Create the data for the empty URI reference
        ByteArrayOutputStream refOutputStream = new ByteArrayOutputStream();
        Transformer xform = TransformerFactory.newInstance().newTransformer();
        xform.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

        xform.transform(new DOMSource(docNode), new StreamResult(refOutputStream));
        InputStream refInputStream = new ByteArrayInputStream(refOutputStream.toByteArray());
        
        // xform.setOutputProperty(OutputKeys.METHOD, "xml");
        // xform.setOutputProperty(OutputKeys.INDENT, "no");
        
        // Transform the Document node to get the content for empty URI reference
        // if (docNode != null) {
        //     xform.transform(new DOMSource(docNode), new StreamResult(refOutputStream));
        // } else {
        //     // If no Document element, use the whole document
        //     xform.transform(new DOMSource(doc), new StreamResult(refOutputStream));
        // }
        
        // byte[] refData = refOutputStream.toByteArray();
        
        // Set the custom dereferencer with the data as byte array
        dsc.setURIDereferencer(new NoUriDereferencer(refInputStream));

        // 6. sign it!
        XMLSignature signature = fac.newXMLSignature(si, ki, objects, null, null);
        signature.sign(dsc);

        if (debugLog) {
            int i = 0;
            for (Reference ref: refs) {
                StringBuilder sb = new StringBuilder();
                String digValStr = digestToString(ref.getDigestValue());
                InputStream is = ref.getDigestInputStream(); 
                if (is != null) {
                    InputStreamReader isr = new InputStreamReader(is);
                    BufferedReader br = new BufferedReader(isr); 
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    is.close();
                }
                i++;
                System.out.println("ref #" + i + " URI: [" + ref.getURI() +"], digest: " + digValStr + ", transformed data: [" + sb.toString() + "]"); 
            }
        }

        return doc;
    }

    // Helper method to convert digest to string
    private static String digestToString(byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}