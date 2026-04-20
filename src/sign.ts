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
import { buildReference, buildSignedInfo, digestReference, type Transform } from "./references.ts";
import { buildSignedProperties, type CommitmentType } from "./signed-properties.ts";

const XMLNS_NS = "http://www.w3.org/2000/xmlns/";

export type SignOptions = {
	input:
		| { xml: string; placement: "ubl-extension" | "root-append" } // enveloped
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
};

export async function sign(opts: SignOptions): Promise<string> {
	const resolved = await resolveSigner(opts);
	const digestAlg = opts.digestAlgorithm ?? "SHA-256";
	const c14nAlg = opts.c14nAlgorithm ?? "exc-c14n";

	const signatureId = makeId("Signature");
	const dataRefId = makeId("Reference");

	const stage = stageDocument(opts, signatureId);

	// KeyInfo
	stage.signatureEl.appendChild(buildKeyInfo(stage.doc, resolved.certificate));

	// SignedProperties → QualifyingProperties → ds:Object
	const sp = await buildSignedProperties(stage.doc, {
		certificate: resolved.certificate,
		digestAlgorithm: digestAlg,
		signingTime: opts.signingTime === null ? undefined : (opts.signingTime ?? new Date()),
		productionPlace: opts.productionPlace,
		commitmentType: opts.commitmentType,
		signerRole: opts.signerRole,
		dataObjectFormat: { referenceId: dataRefId, mimeType: stage.dataRef.mimeType },
	});
	const qpObject = stage.doc.createElementNS(NS.ds, "ds:Object");
	qpObject.setAttribute("Id", makeId("Object"));
	const qp = stage.doc.createElementNS(NS.xades, "xades:QualifyingProperties");
	qp.setAttribute("Target", `#${signatureId}`);
	qp.appendChild(sp.element);
	qpObject.appendChild(qp);
	stage.signatureEl.appendChild(qpObject);

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
	const signatureBytes = await cryptoSign(
		resolved.sigAlg,
		resolved.privateKey,
		canonicalize(si as unknown as Node, c14nAlg),
	);
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

		const dataObjectId = makeId("Object");
		const dataObject = doc.createElementNS(NS.ds, "ds:Object");
		dataObject.setAttribute("Id", dataObjectId);
		dataObject.setAttribute("MimeType", opts.input.mimeType);
		dataObject.setAttribute("Encoding", "http://www.w3.org/2000/09/xmldsig#base64");
		dataObject.appendChild(doc.createTextNode(Buffer.from(opts.input.bytes).toString("base64")));
		signatureEl.appendChild(dataObject);

		return {
			doc,
			signatureEl,
			dataRef: {
				uri: `#${dataObjectId}`,
				mimeType: opts.input.mimeType,
				transforms: [],
				data: dataObject as unknown as Node,
			},
		};
	}

	// Enveloped: parse envelope, create Signature, place by strategy.
	// xmldom types and lib.dom types don't fully agree; stay in xmldom for the
	// parse/placement step, then cast once at the end.
	/* eslint-disable @typescript-eslint/no-explicit-any */
	const xmlDoc: any = new DOMParser().parseFromString(opts.input.xml, "text/xml");
	const root: any = xmlDoc.documentElement;
	const signatureEl: any = xmlDoc.createElementNS(NS.ds, "ds:Signature");
	signatureEl.setAttribute("Id", signatureId);
	signatureEl.setAttributeNS(XMLNS_NS, "xmlns:xades", NS.xades);

	if (opts.input.placement === "ubl-extension") {
		const anchor = xmlDoc.getElementsByTagNameNS(UBL.ext, "ExtensionContent").item(0);
		if (!anchor) throw new Error("ubl-extension: ext:ExtensionContent bulunamadı");
		anchor.appendChild(signatureEl);
	} else {
		root.appendChild(signatureEl);
	}
	const doc: Document = xmlDoc;
	/* eslint-enable @typescript-eslint/no-explicit-any */

	return {
		doc,
		signatureEl,
		dataRef: {
			uri: "",
			mimeType: "text/xml",
			transforms: [{ kind: "enveloped-signature" }, { kind: "c14n", alg: "exc-c14n" }],
			data: root as unknown as Node,
		},
	};
}

function buildKeyInfo(doc: Document, certDer: Uint8Array): Element {
	const ki = doc.createElementNS(NS.ds, "ds:KeyInfo");
	const xd = doc.createElementNS(NS.ds, "ds:X509Data");
	const xc = doc.createElementNS(NS.ds, "ds:X509Certificate");
	xc.appendChild(doc.createTextNode(Buffer.from(certDer).toString("base64")));
	xd.appendChild(xc);
	ki.appendChild(xd);
	return ki;
}

async function resolveSigner(opts: SignOptions): Promise<{
	certificate: Uint8Array;
	privateKey: CryptoKey;
	sigAlg: SignatureAlg;
}> {
	const hash = (opts.digestAlgorithm ?? "SHA-256").replace("-", ""); // "SHA256"
	if ("pfx" in opts.signer) {
		const b = await loadPfx(opts.signer.pfx, opts.signer.password);
		const prefix = b.privateKey.algorithm === "EC" ? "ECDSA" : "RSA";
		const sigAlg = (opts.signatureAlgorithm ?? `${prefix}-${hash}`) as SignatureAlg;
		return {
			certificate: b.certificate,
			privateKey: await importPrivateKey(b.privateKey.pkcs8, sigAlg),
			sigAlg,
		};
	}
	if (!opts.signatureAlgorithm) {
		throw new Error("signatureAlgorithm doğrudan pkcs8 verildiğinde zorunludur");
	}
	return {
		certificate: opts.signer.certificate,
		privateKey: await importPrivateKey(opts.signer.pkcs8, opts.signatureAlgorithm),
		sigAlg: opts.signatureAlgorithm,
	};
}
