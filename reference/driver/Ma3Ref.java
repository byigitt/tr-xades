// tr-xades — MA3 reference driver.
//
// Uses the MA3 library to:
//   1) produce reference XAdES-BES / EPES / T signatures on sample inputs
//   2) dump runtime values obscured by obfuscation (TR policy OIDs, etc.)
//
// This code is NOT part of the tr-xades TypeScript library.
// It is a throwaway tool used to generate test fixtures + learn.
// Run with: ./run.sh
//
// Output: reference/out/*.xml (fixtures), reference/out/meta.json (metadata).

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import tr.gov.tubitak.uekae.esya.api.asn.profile.TurkishESigProfile;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.cmssignature.SignableByteArray;
import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.AllEParameters;
import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.BaseSignedData;
import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.ESignatureType;
import tr.gov.tubitak.uekae.esya.api.common.OID;
import tr.gov.tubitak.uekae.esya.api.common.util.LicenseUtil;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.SignatureAlg;
import tr.gov.tubitak.uekae.esya.api.signature.config.Config;
import tr.gov.tubitak.uekae.esya.api.signature.util.PfxSigner;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.Context;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.SignatureType;
import tr.gov.tubitak.uekae.esya.api.xmlsignature.XMLSignature;

public class Ma3Ref {
  static final String PFX = "../fixtures/test.p12";
  static final String PFX_PASS = "testpass";
  static final String ALIAS = "testsigner";
  static final String INPUT = "../fixtures/sample-invoice.xml";
  static final String OUT = "../out/";

  public static void main(String[] args) throws Exception {
    new File(OUT).mkdirs();
    Map<String, Object> meta = new LinkedHashMap<>();

    // 0) Load MA3's bundled "Genel Kullanım" license (shipped in the public zip).
    try (FileInputStream lis = new FileInputStream("../fixtures/lisans.xml")) {
      if (!LicenseUtil.setLicenseXml(lis)) {
        throw new RuntimeException("MA3 license load failed");
      }
    }
    meta.put("license_expiration", LicenseUtil.getExpirationDate().toString());

    // 1) Dump runtime-decrypted TR policy OIDs.
    meta.put("turkish_esig_policy_oids", dumpPolicyOids());

    // 2) Load signing material.
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (FileInputStream fis = new FileInputStream(PFX)) {
      ks.load(fis, PFX_PASS.toCharArray());
    }
    PrivateKey pk = (PrivateKey) ks.getKey(ALIAS, PFX_PASS.toCharArray());
    X509Certificate jcert = (X509Certificate) ks.getCertificate(ALIAS);
    ECertificate cert = new ECertificate(jcert.getEncoded());
    meta.put("signing_cert_subject", jcert.getSubjectX500Principal().getName());
    meta.put("signing_cert_serial_hex", jcert.getSerialNumber().toString(16));

    // 3) Produce signatures at each level we care about.
    byte[] bes = signEnveloped(SignatureType.XAdES_BES, pk, cert);
    Files.write(Path.of(OUT, "enveloped-bes.xml"), bes);
    meta.put("enveloped_bes_bytes", bes.length);

    try {
      byte[] epes = signEnveloped(SignatureType.XAdES_EPES, pk, cert);
      Files.write(Path.of(OUT, "enveloped-epes.xml"), epes);
      meta.put("enveloped_epes_bytes", epes.length);
    } catch (Exception e) {
      meta.put("enveloped_epes_error", e.getMessage());
    }

    // Enveloping (data inside signature, not wrapped in our envelope).
    try {
      byte[] env = signEnveloping(SignatureType.XAdES_BES, pk, cert);
      Files.write(Path.of(OUT, "enveloping-bes.xml"), env);
      meta.put("enveloping_bes_bytes", env.length);
    } catch (Exception e) {
      meta.put("enveloping_bes_error", e.getMessage());
    }

    // Detached (external reference).
    try {
      byte[] det = signDetached(pk, cert);
      Files.write(Path.of(OUT, "detached-bes.xml"), det);
      meta.put("detached_bes_bytes", det.length);
    } catch (Exception e) {
      meta.put("detached_bes_error", e.getMessage());
    }

    // 4) CAdES-BES fixture (attached). ma3api-cmssignature BaseSignedData + PfxSigner.
    try {
      byte[] cadesBes = signCadesBes("Hello CAdES from MA3 2.3.11.8");
      Files.write(Path.of(OUT, "cades-bes.p7s"), cadesBes);
      meta.put("cades_bes_bytes", cadesBes.length);
    } catch (Exception e) {
      meta.put("cades_bes_error", e.getMessage());
    }

    // 5) Write meta.json.
    Files.writeString(Path.of(OUT, "meta.json"), toJson(meta));
    System.out.println("done — outputs in " + OUT);
    System.out.println(toJson(meta));
  }

  // CAdES-BES attached: data ömmits a CMS SignedData, content embedded.
  static byte[] signCadesBes(String text) throws Exception {
    PfxSigner signer = new PfxSigner(SignatureAlg.RSA_SHA256, PFX, PFX_PASS.toCharArray());
    BaseSignedData bs = new BaseSignedData();
    bs.addContent(new SignableByteArray(text.getBytes("UTF-8")), true);
    // MA3 addSigner default path validation yapar; CertValidationPolicies
    // config’den gelir + P_VALIDATION_WITHOUT_FINDERS ile zincir araması atlanır.
    java.util.Map<String, Object> params = new java.util.HashMap<>();
    Config cfg = new Config();
    params.put(AllEParameters.P_CERT_VALIDATION_POLICIES, cfg.getCertificateValidationPolicies());
    params.put(AllEParameters.P_VALIDATION_WITHOUT_FINDERS, Boolean.TRUE);
    // Self-signed test cert’i kendi trust listesine koy ki path validation 'trusted root'
    // bulsun (Kamu SM bundle'ında değil, elde bünyede).
    java.util.List<ECertificate> trusted = new java.util.ArrayList<>();
    trusted.add(signer.getSignersCertificate());
    params.put(AllEParameters.P_TRUSTED_CERTIFICATES, trusted);
    bs.addSigner(ESignatureType.TYPE_BES, signer.getSignersCertificate(), signer,
                 new java.util.ArrayList<>(), params);
    return bs.getEncoded();
  }

  // XAdES enveloped: signature lives inside the document it signs.
  // Matches the e-Fatura / UBL-TR pattern (ext:ExtensionContent target).
  static byte[] signEnveloped(SignatureType type, PrivateKey pk, ECertificate cert) throws Exception {
    Document doc = loadInvoice();
    Context ctx = new Context(new File(".").getAbsoluteFile());
    ctx.setDocument(doc);

    // root=false: caller chooses where to place the ds:Signature element.
    XMLSignature sig = new XMLSignature(ctx, false);

    // Attach the signature into UBL-TR ext:ExtensionContent.
    Node anchor = findExtensionContent(doc);
    if (anchor != null) {
      anchor.appendChild(sig.getElement());
    } else {
      doc.getDocumentElement().appendChild(sig.getElement());
    }

    // Reference the entire envelope: URI="" with enveloped-signature transform.
    sig.addDocument("", "text/xml", true);

    sig.addKeyInfo(cert);
    sig.sign(pk);

    if (type != SignatureType.XAdES_BES) {
      // upgrade() takes the other SignatureType enum (api.signature.SignatureType).
      // We attempt a cast-compatible upgrade via reflection to avoid import of the
      // ambiguous sibling enum at compile time.
      upgradeReflective(sig, type.name().replaceFirst("XAdES_", "ES_"));
    }

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // Use plain DOM writer so we preserve whole envelope.
    javax.xml.transform.Transformer t =
        javax.xml.transform.TransformerFactory.newInstance().newTransformer();
    t.transform(new javax.xml.transform.dom.DOMSource(doc),
                new javax.xml.transform.stream.StreamResult(bos));
    return bos.toByteArray();
  }

  // XAdES enveloping: signed data embedded inside ds:Object.
  static byte[] signEnveloping(SignatureType type, PrivateKey pk, ECertificate cert) throws Exception {
    Context ctx = new Context(new File(".").getAbsoluteFile());
    XMLSignature sig = new XMLSignature(ctx);

    byte[] payload = Files.readAllBytes(Path.of(INPUT));
    sig.addObject(payload, "text/xml", null);

    sig.addKeyInfo(cert);
    sig.sign(pk);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    sig.write(bos);
    return bos.toByteArray();
  }

  // XAdES detached: external URI reference, document not embedded.
  static byte[] signDetached(PrivateKey pk, ECertificate cert) throws Exception {
    Context ctx = new Context(new File(INPUT).getAbsoluteFile().getParentFile());
    XMLSignature sig = new XMLSignature(ctx);

    sig.addDocument("sample-invoice.xml", "text/xml", false);
    sig.addKeyInfo(cert);
    sig.sign(pk);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    sig.write(bos);
    return bos.toByteArray();
  }

  // Reflective upgrade — avoids depending on api.signature.SignatureType class
  // resolution during compile (the name clashes with api.xmlsignature.SignatureType).
  static void upgradeReflective(XMLSignature sig, String sigTypeName) throws Exception {
    Class<?> enumCls = Class.forName("tr.gov.tubitak.uekae.esya.api.signature.SignatureType");
    Object enumVal = Enum.valueOf((Class) enumCls, sigTypeName);
    sig.getClass().getMethod("upgrade", enumCls).invoke(sig, enumVal);
  }

  static Document loadInvoice() throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setNamespaceAware(true);
    try (InputStream is = new FileInputStream(INPUT)) {
      return f.newDocumentBuilder().parse(is);
    }
  }

  static Node findExtensionContent(Document doc) {
    var list = doc.getElementsByTagNameNS(
        "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
        "ExtensionContent");
    return list.getLength() > 0 ? list.item(0) : null;
  }

  // Read TurkishESigProfile static int[] fields via reflection; convert to dotted OIDs.
  // Static initializer (obfuscated) runs on first class load and populates them.
  static Map<String, String> dumpPolicyOids() throws Exception {
    Map<String, String> out = new LinkedHashMap<>();
    Class<?> cls = TurkishESigProfile.class;
    for (Field f : cls.getDeclaredFields()) {
      if (!f.getName().endsWith("_OID")) continue;
      if (!int[].class.equals(f.getType())) continue;
      f.setAccessible(true);
      int[] arcs = (int[]) f.get(null);
      out.put(f.getName(), oidToString(arcs));
    }
    // Also the profiles list objects — extract OID via OID getter.
    try {
      List<?> profiles = (List<?>) cls.getDeclaredField("profiles").get(null);
      List<String> ps = new ArrayList<>();
      for (Object p : profiles) {
        Object oid = p.getClass().getMethod("getOID").invoke(p);
        int[] v = ((OID) oid).getValue();
        ps.add(oidToString(v));
      }
      out.put("_profiles_list", String.join(",", ps));
    } catch (NoSuchFieldException | NoSuchMethodException ignored) {}
    return out;
  }

  static String oidToString(int[] arcs) {
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < arcs.length; i++) {
      if (i > 0) b.append('.');
      b.append(arcs[i]);
    }
    return b.toString();
  }

  // Tiny JSON dumper (no Jackson).
  @SuppressWarnings("unchecked")
  static String toJson(Object v) {
    if (v == null) return "null";
    if (v instanceof Number || v instanceof Boolean) return v.toString();
    if (v instanceof Map) {
      StringBuilder sb = new StringBuilder("{\n");
      boolean first = true;
      for (var e : ((Map<String, Object>) v).entrySet()) {
        if (!first) sb.append(",\n");
        first = false;
        sb.append("  ").append(jsonStr(e.getKey())).append(": ").append(toJsonInline(e.getValue()));
      }
      return sb.append("\n}\n").toString();
    }
    return jsonStr(v.toString());
  }

  @SuppressWarnings("unchecked")
  static String toJsonInline(Object v) {
    if (v == null) return "null";
    if (v instanceof Number || v instanceof Boolean) return v.toString();
    if (v instanceof Map) {
      StringBuilder sb = new StringBuilder("{");
      boolean first = true;
      for (var e : ((Map<String, Object>) v).entrySet()) {
        if (!first) sb.append(", ");
        first = false;
        sb.append(jsonStr(e.getKey())).append(": ").append(toJsonInline(e.getValue()));
      }
      return sb.append("}").toString();
    }
    return jsonStr(v.toString());
  }

  static String jsonStr(String s) {
    StringBuilder sb = new StringBuilder("\"");
    for (char c : s.toCharArray()) {
      switch (c) {
        case '"': sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
          else sb.append(c);
      }
    }
    return sb.append('"').toString();
  }
}
