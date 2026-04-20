// RFC 3161 Time-Stamp Protocol istemcisi.
//
// Tek fonksiyon: getTimestamp(opts) → Timestamp. HTTP POST ile TSA'ya
// application/timestamp-query MIME type'ıyla DER-encoded TimeStampReq gönderir;
// application/timestamp-reply olarak gelen TimeStampResp'u parse eder.
//
// Token, CMS SignedData içinde TSTInfo barındırır; onu TimeStampToken olarak
// imzaya eklemek için raw bytes döneriz (upgrade.ts XAdES-T için kullanır).

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import type { HashAlg } from "./crypto.ts";
import { KAMUSM } from "./constants.ts";

export type Timestamp = {
	token: Uint8Array; // CMS ContentInfo DER (XAdES EncapsulatedTimeStamp içine konur)
	genTime: Date;
	messageImprint: { algorithm: HashAlg; value: Uint8Array };
	policyOid?: string;
	tsaUrl: string;
};

export type TimestampOptions = {
	digest: Uint8Array;
	digestAlgorithm: HashAlg;
	tsaUrl?: string; // default: Kamu SM
	policyOid?: string;
	nonce?: Uint8Array; // 8 random bytes by default
};

export async function getTimestamp(o: TimestampOptions): Promise<Timestamp> {
	const tsaUrl = o.tsaUrl ?? KAMUSM.tsaUrl;
	const reqBytes = buildRequest(o);

	const resp = await fetch(tsaUrl, {
		method: "POST",
		headers: { "Content-Type": "application/timestamp-query" },
		body: reqBytes as BodyInit,
	});
	if (!resp.ok) throw new Error(`TSA HTTP ${resp.status}: ${await safeText(resp)}`);
	const respBytes = new Uint8Array(await resp.arrayBuffer());
	return parseResponse(respBytes, tsaUrl);
}

export function buildRequest(o: TimestampOptions): Uint8Array {
	const req = new pkijs.TimeStampReq({
		version: 1,
		messageImprint: new pkijs.MessageImprint({
			hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: hashOid(o.digestAlgorithm) }),
			hashedMessage: new asn1js.OctetString({ valueHex: o.digest.buffer as ArrayBuffer }),
		}),
		certReq: true,
		nonce: new asn1js.Integer({ valueHex: (o.nonce ?? randomNonce()).buffer as ArrayBuffer }),
		...(o.policyOid ? { reqPolicy: o.policyOid } : {}),
	});
	return new Uint8Array(req.toSchema().toBER());
}

export function parseResponse(bytes: Uint8Array, tsaUrl: string): Timestamp {
	const asn = asn1js.fromBER(toAB(bytes));
	if (asn.offset === -1) throw new Error("TSA response: ASN.1 parse hatası");
	const resp = new pkijs.TimeStampResp({ schema: asn.result });

	if (resp.status.status !== 0 && resp.status.status !== 1) {
		// 0 = granted, 1 = granted with mods; her şey geçerli
		const msg = resp.status.statusStrings?.map((s) => s.valueBlock.value).join("; ") ?? "";
		throw new Error(`TSA status=${resp.status.status} ${msg}`);
	}
	if (!resp.timeStampToken) throw new Error("TSA cevabı TimeStampToken içermiyor");

	const tokenBytes = new Uint8Array(resp.timeStampToken.toSchema().toBER());

	// TSTInfo = TimeStampToken içindeki CMS SignedData.encapContentInfo.eContent.
	const sd = new pkijs.SignedData({ schema: resp.timeStampToken.content });
	const eContent = sd.encapContentInfo.eContent;
	if (!eContent) throw new Error("TimeStampToken içinde TSTInfo yok");
	const tstBytes = eContent.valueBlock.valueHexView;
	const tst = new pkijs.TSTInfo({ schema: asn1js.fromBER(toAB(new Uint8Array(tstBytes))).result });

	return {
		token: tokenBytes,
		genTime: tst.genTime,
		messageImprint: {
			algorithm: hashAlgFromOid(tst.messageImprint.hashAlgorithm.algorithmId),
			value: new Uint8Array(tst.messageImprint.hashedMessage.valueBlock.valueHexView),
		},
		...(tst.policy ? { policyOid: tst.policy } : {}),
		tsaUrl,
	};
}

function hashOid(alg: HashAlg): string {
	return alg === "SHA-256" ? "2.16.840.1.101.3.4.2.1"
		: alg === "SHA-384" ? "2.16.840.1.101.3.4.2.2"
		: "2.16.840.1.101.3.4.2.3";
}
function hashAlgFromOid(oid: string): HashAlg {
	if (oid === "2.16.840.1.101.3.4.2.1") return "SHA-256";
	if (oid === "2.16.840.1.101.3.4.2.2") return "SHA-384";
	if (oid === "2.16.840.1.101.3.4.2.3") return "SHA-512";
	throw new Error(`desteklenmeyen TSA hash OID: ${oid}`);
}

function randomNonce(): Uint8Array {
	const u = new Uint8Array(8);
	globalThis.crypto.getRandomValues(u);
	return u;
}

function toAB(u8: Uint8Array): ArrayBuffer {
	const ab = new ArrayBuffer(u8.byteLength);
	new Uint8Array(ab).set(u8);
	return ab;
}

async function safeText(r: Response): Promise<string> {
	try { return await r.text(); } catch { return "(no body)"; }
}
