// XAdES-BES imzalama orchestratörü.
//
// Tek `sign()` fonksiyonu — seviye/profil/algoritma hepsi parametre. Şimdilik
// sadece BES. EPES (faz 5) policy; T/LT/LTA (faz 6/7) sonra eklenecek.
//
// Akış: stageDocument → KeyInfo → SignedProperties/QualifyingProperties →
// data & sp digests → SignedInfo → canonicalize(SI) → sign → SignatureValue.

import { DOMImplementation, DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { canonicalize, type C14NAlg } from "./c14n.ts";
import { NS, SIGNED_PROPS_TYPE, UBL } from "./constants.ts";
import {
	importPrivateKey,
	sign as cryptoSign,
	type HashAlg,
	type SignatureAlg,
} from "./crypto.ts";
import { makeId } from "./ids.ts";
import { loadPfx } from "./pfx.ts";
import type { Pkcs11Handle } from "./pkcs11.ts";
import { trPolicy, type Policy, type Profile } from "./policy.ts";
import { buildReference, buildSignedInfo, digestReference, type Transform } from "./references.ts";
import { buildSignedProperties, type CommitmentType } from "./signed-properties.ts";

const XMLNS_NS = "http://www.w3.org/2000/xmlns/";

export type SignOptions = {
	input:
		| { xml: string; placement: "ubl-extension" | "root-append" } // W3C enveloped
		| { xml: string; placement: "ubl-ma3-compat" } // UBL envelope + enveloping-embedded (MA3 interop)
		| { bytes: Uint8Array; mimeType: string } // enveloping (data embedded)
		| { uri: string; data: Uint8Array; mimeType: string }; // detached (external URI)
	signer:
		| { pfx: Uint8Array; password: string }
		| { pkcs8: Uint8Array; certificate: Uint8Array };
	digestAlgorithm?: HashAlg;
	signatureAlgorithm?: SignatureAlg;
	c14nAlgorithm?: C14NAlg;
	signingTime?: Date | null; // null = omit; default = new Date()
	productionPlace?: { city?: string; state?: string; postalCode?: string; country?: string };
	commitmentType?: CommitmentType;
	signerRole?: { claimed: string[] };
	// Presence triggers XAdES-EPES (adds SignaturePolicyIdentifier). String =
	// TR preset (trPolicy lookup); object = custom policy.
	policy?: Profile | Policy;
};

export async function sign(opts: SignOptions): Promise<string> {
	const resolved = await resolveSigner({
		signer: opts.signer,
		digestAlgorithm: opts.digestAlgorithm,
		signatureAlgorithm: opts.signatureAlgorithm,
	});
	const digestAlg = opts.digestAlgorithm ?? "SHA-256";
	const c14nAlg = opts.c14nAlgorithm ?? "exc-c14n";

	const signatureId = makeId("Signature");
	const dataRefId = makeId("Reference");

	const stage = stageDocument(opts, signatureId);

	// SignedProperties → QualifyingProperties → ds:Object
	const sp = await buildSignedProperties(stage.doc, {
		certificate: resolved.certificate,
		digestAlgorithm: digestAlg,
		signingTime: opts.signingTime === null ? undefined : (opts.signingTime ?? new Date()),
		productionPlace: opts.productionPlace,
		commitmentType: opts.commitmentType,
		signerRole: opts.signerRole,
		dataObjectFormat: { referenceId: dataRefId, mimeType: stage.dataRef.mimeType },
		policy: typeof opts.policy === "string" ? trPolicy(opts.policy) : opts.policy,
	});
	const qpObject = stage.doc.createElementNS(NS.ds, "ds:Object");
	qpObject.setAttribute("Id", makeId("Object"));
	const qp = stage.doc.createElementNS(NS.xades, "xades:QualifyingProperties");
	qp.setAttribute("Target", `#${signatureId}`);
	qp.appendChild(sp.element);
	qpObject.appendChild(qp);

	// XMLDSig şema sırası: SignedInfo, SignatureValue, KeyInfo, Object*.
	// SignedInfo + SignatureValue aşağıdaki adımda őne eklenir.
	stage.signatureEl.appendChild(buildKeyInfo(stage.doc, resolved.certificate));
	stage.signatureEl.appendChild(qpObject);
	if (stage.dataObject) stage.signatureEl.appendChild(stage.dataObject);

	// Data ref digest. Inject real signatureId into enveloped-signature transforms.
	const dataTransforms: Transform[] = stage.dataRef.transforms.map((t) =>
		t.kind === "enveloped-signature" ? { kind: "enveloped-signature", signatureId } : t,
	);
	const dataDigest = await digestReference(stage.dataRef.data, dataTransforms, digestAlg);
	const dataRefEl = buildReference(stage.doc, {
		uri: stage.dataRef.uri,
		id: dataRefId,
		digestAlg,
		digestValue: dataDigest,
		transforms: dataTransforms,
	});

	const spDigest = await sp.c14nDigest(digestAlg, c14nAlg);
	const spRefEl = buildReference(stage.doc, {
		uri: `#${sp.id}`,
		id: makeId("Reference"),
		type: SIGNED_PROPS_TYPE,
		digestAlg,
		digestValue: spDigest,
		transforms: [{ kind: "c14n", alg: c14nAlg }],
	});

	// SignedInfo as first child.
	const si = buildSignedInfo(stage.doc, {
		references: [dataRefEl, spRefEl],
		signatureAlg: resolved.sigAlg,
		c14nAlg,
	});
	stage.signatureEl.insertBefore(si, stage.signatureEl.firstChild);

	// Sign canonicalized SignedInfo.
	const signatureBytes = await resolved.sign(canonicalize(si as unknown as Node, c14nAlg));
	const sv = stage.doc.createElementNS(NS.ds, "ds:SignatureValue");
	sv.setAttribute("Id", makeId("Signature-Value"));
	sv.appendChild(stage.doc.createTextNode(Buffer.from(signatureBytes).toString("base64")));
	si.parentNode!.insertBefore(sv, si.nextSibling);

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	return new XMLSerializer().serializeToString(stage.doc as any);
}

type Stage = {
	doc: Document;
	signatureEl: Element;
	dataRef: { uri: string; mimeType: string; transforms: Transform[]; data: Node | Uint8Array };
	dataObject?: Element; // enveloping/ubl-ma3-compat'ta signature sonuna eklenir
};

function stageDocument(opts: SignOptions, signatureId: string): Stage {
	if ("uri" in opts.input) {
		// Detached: Signature root, data lives externally (bytes carried for digest).
		const doc = new DOMImplementation().createDocument(NS.ds, "ds:Signature", null) as unknown as Document;
		const signatureEl = doc.documentElement!;
		signatureEl.setAttribute("Id", signatureId);
		signatureEl.setAttributeNS(XMLNS_NS, "xmlns:xades", NS.xades);
		return {
			doc,
			signatureEl,
			dataRef: {
				uri: opts.input.uri,
				mimeType: opts.input.mimeType,
				transforms: [],
				data: opts.input.data,
			},
		};
	}

	if ("bytes" in opts.input) {
		// Enveloping: Signature root, data in a ds:Object (base64).
		const doc = new DOMImplementation().createDocument(NS.ds, "ds:Signature", null) as unknown as Document;
		const signatureEl = doc.documentElement!;
		signatureEl.setAttribute("Id", signatureId);
		signatureEl.setAttributeNS(XMLNS_NS, "xmlns:xades", NS.xades);

		const dataObject = makeDataObject(doc, opts.input.bytes, opts.input.mimeType);
		return {
			doc,
			signatureEl,
			dataObject,
			dataRef: {
				uri: `#${dataObject.getAttribute("Id")}`,
				mimeType: opts.input.mimeType,
				transforms: [],
				data: dataObject as unknown as Node,
			},
		};
	}

	if (opts.input.placement === "ubl-ma3-compat") {
		// Enveloping-embedded-in-envelope: envelope'u parse et, ds:Signature'ı
		// ExtensionContent içine yerleştir, input XML'ini base64 halinde ds:Object
		// içinde tut, reference #ObjectId. MA3 verifier bu yapıyı kabul eder.
		const { doc, signatureEl } = parseAndStageEnveloped(opts.input, signatureId, "ubl-ma3-compat");
		const dataObject = makeDataObject(doc, new TextEncoder().encode(opts.input.xml), "text/xml");
		return {
			doc,
			signatureEl,
			dataObject,
			dataRef: {
				uri: `#${dataObject.getAttribute("Id")}`,
				mimeType: "text/xml",
				transforms: [],
				data: dataObject as unknown as Node,
			},
		};
	}

	// W3C enveloped (placement: ubl-extension veya root-append).
	const { doc, signatureEl, root } = parseAndStageEnveloped(opts.input, signatureId, opts.input.placement);
	return {
		doc,
		signatureEl,
		dataRef: {
			uri: "",
			mimeType: "text/xml",
			transforms: [{ kind: "enveloped-signature" }, { kind: "c14n", alg: "exc-c14n" }],
			data: root,
		},
	};
}

function makeDataObject(doc: Document, data: Uint8Array, mimeType: string): Element {
	const id = makeId("Object");
	const el = doc.createElementNS(NS.ds, "ds:Object");
	el.setAttribute("Id", id);
	el.setAttribute("MimeType", mimeType);
	el.setAttribute("Encoding", "http://www.w3.org/2000/09/xmldsig#base64");
	el.appendChild(doc.createTextNode(Buffer.from(data).toString("base64")));
	return el;
}

// Envelope'u parse et, ds:Signature üret, placement moduna göre yerleştir.
// xmldom ile lib.dom tiplerini karıştırmamak için içeride any kullanılır.
function parseAndStageEnveloped(
	input: { xml: string },
	signatureId: string,
	placement: "ubl-extension" | "root-append" | "ubl-ma3-compat",
// eslint-disable-next-line @typescript-eslint/no-explicit-any
): { doc: Document; signatureEl: Element; root: any } {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const xmlDoc: any = new DOMParser().parseFromString(input.xml, "text/xml");
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const root: any = xmlDoc.documentElement;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const signatureEl: any = xmlDoc.createElementNS(NS.ds, "ds:Signature");
	signatureEl.setAttribute("Id", signatureId);
	signatureEl.setAttributeNS(XMLNS_NS, "xmlns:xades", NS.xades);

	if (placement === "ubl-extension" || placement === "ubl-ma3-compat") {
		const anchor = xmlDoc.getElementsByTagNameNS(UBL.ext, "ExtensionContent").item(0);
		if (!anchor) throw new Error(`${placement}: ext:ExtensionContent bulunamadı`);
		anchor.appendChild(signatureEl);
	} else {
		root.appendChild(signatureEl);
	}
	return { doc: xmlDoc, signatureEl, root };
}

export function buildKeyInfo(doc: Document, certDer: Uint8Array): Element {
	const ki = doc.createElementNS(NS.ds, "ds:KeyInfo");
	const xd = doc.createElementNS(NS.ds, "ds:X509Data");
	const xc = doc.createElementNS(NS.ds, "ds:X509Certificate");
	xc.appendChild(doc.createTextNode(Buffer.from(certDer).toString("base64")));
	xd.appendChild(xc);
	ki.appendChild(xd);
	return ki;
}

export type SignerInput =
	| { pfx: Uint8Array; password: string }
	| { pkcs8: Uint8Array; certificate: Uint8Array }
	| { pkcs11: Pkcs11Handle; label?: string; subject?: RegExp };

/**
 * Resolved signer:
 *   - certificate: X.509 DER
 *   - sigAlg: 'RSA-SHA256' gibi
 *   - sign: hem WebCrypto hem PKCS#11 için tek interface
 *   - privateKey: pkijs uyumlu yol (pfx/pkcs8). PKCS#11'de undefined;
 *                 çağrıcı manuel signedAttrs DER yolunu kullanmalı.
 */
export type ResolvedSigner = {
	certificate: Uint8Array;
	sigAlg: SignatureAlg;
	sign: (data: Uint8Array) => Promise<Uint8Array>;
	privateKey?: CryptoKey;
};

export async function resolveSigner(input: {
	signer: SignerInput;
	digestAlgorithm?: HashAlg;
	signatureAlgorithm?: SignatureAlg;
}): Promise<ResolvedSigner> {
	const hash = (input.digestAlgorithm ?? "SHA-256").replace("-", ""); // "SHA256"
	if ("pfx" in input.signer) {
		const b = await loadPfx(input.signer.pfx, input.signer.password);
		const prefix = b.privateKey.algorithm === "EC" ? "ECDSA" : "RSA";
		const sigAlg = (input.signatureAlgorithm ?? `${prefix}-${hash}`) as SignatureAlg;
		const privateKey = await importPrivateKey(b.privateKey.pkcs8, sigAlg);
		return {
			certificate: b.certificate,
			privateKey,
			sigAlg,
			sign: (data) => cryptoSign(sigAlg, privateKey, data),
		};
	}
	if ("pkcs8" in input.signer) {
		if (!input.signatureAlgorithm) {
			throw new Error("signatureAlgorithm doğrudan pkcs8 verildiğinde zorunludur");
		}
		const sigAlg = input.signatureAlgorithm;
		const privateKey = await importPrivateKey(input.signer.pkcs8, sigAlg);
		return {
			certificate: input.signer.certificate,
			privateKey,
			sigAlg,
			sign: (data) => cryptoSign(sigAlg, privateKey, data),
		};
	}
	// PKCS#11
	const { findSigner, pkcs11Sign } = await import("./pkcs11.ts");
	const found = findSigner(input.signer.pkcs11.session, {
		...(input.signer.label !== undefined && { label: input.signer.label }),
		...(input.signer.subject !== undefined && { subject: input.signer.subject }),
	});
	// SHA256_RSA_PKCS = 0x40 (64) → RSA. ECDSA_SHA256 = 0x1044 (4164) → ECDSA.
	const sigAlg: SignatureAlg = input.signatureAlgorithm
		?? (found.mechanism === 0x1044 ? "ECDSA-SHA256" : "RSA-SHA256");
	const session = input.signer.pkcs11.session;
	return {
		certificate: found.certificate,
		sigAlg,
		sign: async (data) => pkcs11Sign(session, found, data),
	};
}
