package com.market.analytics;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

/**
 * This is a simple example of generating an Enveloping XML
 * Signature using the JSR 105 API. The signature in this case references a
 * local URI that points to an Object element.
 * The resulting signature will look like (certificate and
 * signature values will be different):
 *
 * <pre><code>
 *     <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
 * 	<SignedInfo>
 * 		<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n- 20010315"/>
 * 		<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
 * 		<Reference Id="Reference_1" Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#Object_1">
 * 			<Transforms>
 * 				<Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
 * 			</Transforms>
 * 			<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 * 			<DigestValue>UyIxOvUWBsExrVZ+Vo3PhRHM6gfMm9SrpbMUy+k5/Do=</DigestValue>
 * 		</Reference>
 * 	</SignedInfo>
 * 	<SignatureValue Id="SignatureValue_1">
 * o4VW73oWs3nReSghpDOeq65k71KBkZEbOkbO2T6WKekh6zx9Eo9by9crP8b5YhvMWRJ4CPKWKyZV
 * 	</SignatureValue>
 * 	<KeyInfo>
 * 		<KeyValue>
 * 			<RSAKeyValue>
 * 				<Modulus>
 * 5+H3JFG1mdyIsMdYIH+DjWF+LsIzfbkuUmzMnNTSPdyA3B9tjhrIYOoWEPGSwepq+3ZQAUxYm47Q
 * 				</Modulus>
 * 				<Exponent>AQAB</Exponent>
 * 			</RSAKeyValue>
 * 		</KeyValue>
 *
 * 		<X509Data>
 * 			<X509Certificate>
 * MIIHtDCCBpygAwIBAgIGVw5slxGcMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAkhVMREwDwYD
 * bbhxf3ewWkNLdY/Q9LdRVYfZ51Bv6jQ06KHG2Jd3LhqyW/nlAGeVamATq/29Jc02KADTzjyCsDoR fnafAZQ7ZSSmDomDVMnjuCQkYrE+qza4Ct94mGe1xCw73u9gaCRKwadj/ex370MNQ/8YPo7QTnut
 * /z/SvhtOZtbGaU1La3QefEuP48uSpX0Ig+s57t9FkVv4vt4Gbp4=
 * 			</X509Certificate>
 * 		</X509Data>
 * 	</KeyInfo>
 * 	<Object Id="Object_1">
 * 		<messagebody>
 * 			<message_type>1</message_type>
 * 			<provider_1>900</provider_1>
 * 			<provider_2>916</provider_2>
 * 			<provider_3>900</provider_3>
 * 			<startr>12054030</startr>
 * 			<stopr>12054030</stopr>
 * 			<validd>2018-10-10 20:00:00</validd>
 * 			<tr_id>TR_1538959634859</tr_id>
 * 			<user_dn>EMAILADDRESS=user@nmhh.hu, UID=90001, CN=NMHH(900)-KRA-USER1, OU=KRA,
 * O=Nemzeti Media- es Hirkozlesi Hatosag, C=HU</user_dn>
 * 			<equip>090</equip>
 * 		</messagebody>
 * 	</Object>
 * </Signature>
 * </code></pre>
 */
public class GenEnveloping {

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

        // Create a RSA KeyPair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        // Create a KeyValue containing the DSA PublicKey that was generated
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());

        // Create a KeyInfo and add the KeyValue to it
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        // Create the XMLSignature (but don't sign it yet)
        XMLSignature signature = fac.newXMLSignature(si, ki,
                Collections.singletonList(obj), null, "SignatureValue_1");

        // Create a DOMSignContext and specify the DSA PrivateKey for signing
        // and the document location of the XMLSignature
        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), doc);

        // Lastly, generate the enveloping signature using the PrivateKey
        signature.sign(dsc);

        // output the resulting document
        OutputStream os;
        if (args.length > 0) {
            os = new FileOutputStream(args[0]);
        } else {
            os = System.out;
        }

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
    }
}
