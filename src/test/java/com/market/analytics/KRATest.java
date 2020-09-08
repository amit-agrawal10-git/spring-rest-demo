package com.market.analytics;

import org.w3c.dom.Document;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This is a simple example of generating an Enveloping XML
 * Signature using the JSR 105 API. The signature in this case references a
 * local URI that points to an Object element.
 * The resulting signature will look like (certificate and
 * signature values will be different):
 *
 */
    public class KRATest implements Serializable {

    //
    // Synopis: java GenEnveloping [output]
    //
    //   where "output" is the name of a file that will contain the
    //   generated signature. If not specified, standard output will be used.
    //
    public static void main(String[] args) throws Exception {

        // First, create the DOM XMLSignatureFactory that will be used to
        // generate the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Next, create a Reference to a same-document URI that is an Object
        // element and specify the SHA1 digest algorithm
        Reference ref = fac.newReference(
                "#Object_1",
                    fac.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList
                        (fac.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                                (TransformParameterSpec) null)), "http://www.w3.org/2000/09/xmldsig#Object", "Reference_1");

        // Next, create the referenced Object
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new File("Z:\\Work\\Projects\\analytics-springboot\\src\\test\\java\\com\\market\\analytics\\Input.xml"));
        XMLStructure content = new DOMStructure(doc.getDocumentElement());
        XMLObject obj = fac.newXMLObject
                (Collections.singletonList(content), "Object_1", null, null);

        // Create the SignedInfo
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod
                        (CanonicalizationMethod.INCLUSIVE,
                                (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(ref));

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("Z:\\Work\\Projects\\analytics-springboot\\src\\test\\java\\com\\market\\analytics\\keystore.jks"), "netcracker".toCharArray());
        Key key = (PrivateKey) ks.getKey("mydomain", "netcracker".toCharArray());
        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry
                        ("mydomain", new KeyStore.PasswordProtection("netcracker".toCharArray()));
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
       // x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);

        // Create a KeyValue containing the DSA PublicKey that was generated
        KeyValue kv = kif.newKeyValue(cert.getPublicKey());
        List list = new ArrayList();
        list.add(kv);
        list.add(xd);
        KeyInfo ki = kif.newKeyInfo(list);

      //  System.out.println(cert);

       /* // Create a RSA KeyPair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        // Create a KeyValue containing the DSA PublicKey that was generated
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
*/
        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki,
                Collections.singletonList(obj), null, "SignatureValue_1");

        // Create a DOMSignContext and specify the DSA PrivateKey for signing
        // and the document location of the XMLSignature
        DOMSignContext dsc = new DOMSignContext(key, doc);

        // Lastly, generate the enveloping signature using the PrivateKey
        signature.sign(dsc);

        // output the resulting document
        OutputStream os;
        if (args.length > 0) {
            os = new FileOutputStream(args[0]);
        } else {
            os = System.out;
        }


        //SerializationUtils.deserialize(SerializationUtils.serialize())
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
    }
}
