package com.example.spring.xades;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import java.io.InputStream;
// import java.io.ByteArrayInputStream;
// import java.io.ByteArrayOutputStream;

// public class NoUriDereferencer implements URIDereferencer {

//     private final byte[] refData;

//     // Constructor that accepts byte array (as expected by the updated XadesBesSigner)
//     public NoUriDereferencer(byte[] refData) {
//         this.refData = refData;
//     }

//     // Constructor that accepts InputStream (for backward compatibility)
//     public NoUriDereferencer(InputStream inputStream) {
//         try {
//             ByteArrayOutputStream baos = new ByteArrayOutputStream();
//             byte[] buffer = new byte[1024];
//             int length;
//             while ((length = inputStream.read(buffer)) != -1) {
//                 baos.write(buffer, 0, length);
//             }
//             this.refData = baos.toByteArray();
//             inputStream.close();
//         } catch (Exception e) {
//             throw new RuntimeException("Failed to read InputStream", e);
//         }
//     }

//     @Override
//     public Data dereference(URIReference uriRef, XMLCryptoContext context) throws URIReferenceException {
//         // Create a fresh InputStream each time this method is called
//         // This is important because the stream might be read multiple times during signing
//         return new OctetStreamData(new ByteArrayInputStream(refData));
//     }
// }

public class NoUriDereferencer implements URIDereferencer {
    private InputStream inputStream;
    public NoUriDereferencer(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public Data dereference(URIReference uriRef, XMLCryptoContext ctx) throws URIReferenceException {
        if (uriRef.getURI() != null) {
            URIDereferencer defaultDereferencer = XMLSignatureFactory.getInstance("DOM").getURIDereferencer();
            return defaultDereferencer.dereference(uriRef, ctx);
        }
        Data data = new OctetStreamData(inputStream);
        return data;
    }
}