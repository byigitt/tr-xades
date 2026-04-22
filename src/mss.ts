// Mobil İmza (MSS) istemcisi. ETSI TS 102 204 v1.1.2 SOAP protokolü.
// TR operatörleri: Turkcell, Vodafone, Türk Telekom / Turk.net.
//
// Referans: MA3 ma3api-mssclient-2.3.11.8 + ma3api-*mssprovider-*/ (decompile
// gözlemi). ETSI §5 MSS_SignatureReq/Resp + MSS_StatusReq/Resp.
//
// Hand-rolled SOAP XML builder + native fetch. Dep YOK.

import { DOMParser } from "@xmldom/xmldom";

const NS = {
	soap: "http://schemas.xmlsoap.org/soap/envelope/",
	mss: "http://uri.etsi.org/TS102204/v1.1.2#",
} as const;

/** ETSI §5.1 MessagingModeType */
export type MessagingMode = "synch" | "asynchClientServer" | "asynchServerServer";

export type MssSignOptions = {
	/** MSSP SOAP endpoint (https://mobilimza.turkcell.com.tr/... gibi) */
	serviceUrl: string;
	/** AP_ID — sağlayıcının verdiği Application Provider ID */
	apId: string;
	/** AP_PWD — Application Provider parola/secret */
	apPwd: string;
	/** MSISDN — imzalayıcı telefon (ör. "905551234567") */
	msisdn: string;
	/** İmzalanacak veri (hash önceden hesaplandıysa binary; metin ise UTF-8 buffer) */
	dataToBeSigned: Uint8Array;
	/** DataType MimeType — default "application/octet-stream"; metin için "text/plain" */
	dataMimeType?: string;
	/** Kullanıcıya gösterilecek text — opsiyonel (text/plain) */
	dataToBeDisplayed?: string;
	/** ETSI signatureProfile URI — provider tanımlı; default TR mali mühür profili */
	signatureProfile?: string;
	/** MSS_Format URI — default PKCS7 (CMS) */
	mssFormat?: string;
	/** ETSI messaging mode */
	messagingMode?: MessagingMode;
	/** AP_TransID — idempotency. Verilmezse UUID v4 üretilir. */
	apTransId?: string;
	/** TimeOut saniye — async modda timeout */
	timeOutSec?: number;
	/** fetch override (test mock için) */
	fetch?: typeof fetch;
};

export type MssSignResult = {
	/** PKCS#7 / CMS SignedData DER (MSS_Format PKCS7) */
	signature: Uint8Array;
	/** MSSP_TransID — async için mssStatus çağrısında kullanılır */
	msspTransId: string;
	/** Cihazdan dönen durum kodu (ETSI §5.2.2, ör. "100" başarılı) */
	statusCode?: string;
	/** Durum mesajı */
	statusMessage?: string;
};

export type MssStatusOptions = {
	serviceUrl: string;
	apId: string;
	apPwd: string;
	/** mssSign'dan dönen MSSP_TransID */
	msspTransId: string;
	apTransId?: string;
	fetch?: typeof fetch;
};

export type MssStatusResult = {
	/** ETSI §5.2.2 StatusCode/@Value (örn. "500" = signature in progress, "502" = OK) */
	statusCode: string;
	statusMessage: string;
	/** İmza hazırsa PKCS#7/CMS DER. "in progress" durumunda undefined. */
	signature?: Uint8Array;
};

export type MssProfileQueryOptions = {
	serviceUrl: string;
	apId: string;
	apPwd: string;
	msisdn: string;
	apTransId?: string;
	fetch?: typeof fetch;
};

export type MssProfileQueryResult = {
	msspTransId: string;
	statusCode?: string;
	statusMessage?: string;
	profiles: string[];
};

export type MssSignerCertOptions = {
	serviceUrl: string;
	apId: string;
	apPwd: string;
	msisdn: string;
	apTransId?: string;
	fetch?: typeof fetch;
};

export type MssSignerCertResult = {
	msspTransId: string;
	statusCode?: string;
	statusMessage?: string;
	certificate?: Uint8Array;
	certificateUri?: string;
};

/**
 * ETSI §5.2 MSS_StatusReq — async mod'daki bir imzanın durumunu sorgular.
 * Polling manuel yapılır; mssPoll() helper'ı bekleyerek imza gelene kadar tekrarlar.
 */
export async function mssStatus(opts: MssStatusOptions): Promise<MssStatusResult> {
	const apTransId = opts.apTransId ?? uuid();
	const instant = new Date().toISOString();
	const envelope = buildStatusReq({
		apId: opts.apId, apPwd: opts.apPwd, apTransId, instant,
		msspTransId: opts.msspTransId,
	});
	const xml = await postSoap(opts.serviceUrl, envelope, "MSS_StatusQuery", opts.fetch);
	return parseStatusResp(xml);
}

/** mssPoll — mssStatus'u ihtiyaç halinde tekrarlar; imza dönene dek veya timeout. */
export async function mssPoll(
	opts: MssStatusOptions & { intervalMs?: number; timeoutMs?: number },
): Promise<MssStatusResult> {
	const interval = opts.intervalMs ?? 3000;
	const timeout = opts.timeoutMs ?? 120_000;
	const deadline = Date.now() + timeout;
	// eslint-disable-next-line no-constant-condition
	while (true) {
		const r = await mssStatus(opts);
		if (r.signature) return r;
		if (Date.now() >= deadline) throw new Error(`mssPoll: timeout (${timeout}ms) status=${r.statusCode}`);
		await new Promise((res) => setTimeout(res, interval));
	}
}

export async function mssProfileQuery(opts: MssProfileQueryOptions): Promise<MssProfileQueryResult> {
	const apTransId = opts.apTransId ?? uuid();
	const instant = new Date().toISOString();
	const envelope = buildProfileQueryReq({
		apId: opts.apId,
		apPwd: opts.apPwd,
		apTransId,
		instant,
		msisdn: opts.msisdn,
	});
	const respXml = await postSoap(opts.serviceUrl, envelope, "MSS_ProfileQuery", opts.fetch);
	return parseProfileQueryResp(respXml);
}

export async function mssSignerCert(opts: MssSignerCertOptions): Promise<MssSignerCertResult> {
	const apTransId = opts.apTransId ?? uuid();
	const instant = new Date().toISOString();
	const envelope = buildRegistrationReq({
		apId: opts.apId,
		apPwd: opts.apPwd,
		apTransId,
		instant,
		msisdn: opts.msisdn,
	});
	const respXml = await postSoap(opts.serviceUrl, envelope, "MSS_Registration", opts.fetch);
	return parseRegistrationResp(respXml);
}

export async function mssSign(opts: MssSignOptions): Promise<MssSignResult> {
	const apTransId = opts.apTransId ?? uuid();
	const instant = new Date().toISOString();
	const envelope = buildSignatureReq({
		apId: opts.apId,
		apPwd: opts.apPwd,
		apTransId,
		instant,
		msisdn: opts.msisdn,
		dataToBeSigned: opts.dataToBeSigned,
		dataMimeType: opts.dataMimeType ?? "application/octet-stream",
		...(opts.dataToBeDisplayed !== undefined && { dataToBeDisplayed: opts.dataToBeDisplayed }),
		signatureProfile: opts.signatureProfile ?? "http://uri.etsi.org/TS102204/v1.1.2#signature-profile",
		mssFormat: opts.mssFormat ?? "http://uri.etsi.org/TS102204/v1.1.2#PKCS7",
		messagingMode: opts.messagingMode ?? "synch",
		...(opts.timeOutSec !== undefined && { timeOutSec: opts.timeOutSec }),
	});
	const respXml = await postSoap(opts.serviceUrl, envelope, "MSS_Signature", opts.fetch);
	return parseSignatureResp(respXml);
}

function buildStatusReq(a: {
	apId: string; apPwd: string; apTransId: string; instant: string; msspTransId: string;
}): string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="${NS.soap}" xmlns:mss="${NS.mss}">
  <soap:Body>
    <mss:MSS_StatusQuery>
      <mss:MSS_StatusReq MajorVersion="1" MinorVersion="1">
        <mss:AP_Info AP_ID="${xmlEscape(a.apId)}" AP_TransID="${xmlEscape(a.apTransId)}" AP_PWD="${xmlEscape(a.apPwd)}" Instant="${a.instant}"/>
        <mss:MSSP_Info><mss:MSSP_ID><mss:URI>${NS.mss}</mss:URI></mss:MSSP_ID></mss:MSSP_Info>
        <mss:MSSP_TransID>${xmlEscape(a.msspTransId)}</mss:MSSP_TransID>
      </mss:MSS_StatusReq>
    </mss:MSS_StatusQuery>
  </soap:Body>
</soap:Envelope>`;
}

function buildProfileQueryReq(a: {
	apId: string; apPwd: string; apTransId: string; instant: string; msisdn: string;
}): string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="${NS.soap}" xmlns:mss="${NS.mss}">
  <soap:Body>
    <mss:MSS_ProfileQuery>
      <mss:MSS_ProfileReq MajorVersion="1" MinorVersion="1">
        <mss:AP_Info AP_ID="${xmlEscape(a.apId)}" AP_TransID="${xmlEscape(a.apTransId)}" AP_PWD="${xmlEscape(a.apPwd)}" Instant="${a.instant}"/>
        <mss:MSSP_Info><mss:MSSP_ID><mss:URI>${NS.mss}</mss:URI></mss:MSSP_ID></mss:MSSP_Info>
        <mss:MobileUser><mss:MSISDN>${xmlEscape(a.msisdn)}</mss:MSISDN></mss:MobileUser>
      </mss:MSS_ProfileReq>
    </mss:MSS_ProfileQuery>
  </soap:Body>
</soap:Envelope>`;
}

function buildRegistrationReq(a: {
	apId: string; apPwd: string; apTransId: string; instant: string; msisdn: string;
}): string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="${NS.soap}" xmlns:mss="${NS.mss}">
  <soap:Body>
    <mss:MSS_Registration>
      <mss:MSS_RegistrationReq MajorVersion="1" MinorVersion="1">
        <mss:AP_Info AP_ID="${xmlEscape(a.apId)}" AP_TransID="${xmlEscape(a.apTransId)}" AP_PWD="${xmlEscape(a.apPwd)}" Instant="${a.instant}"/>
        <mss:MSSP_Info><mss:MSSP_ID><mss:URI>${NS.mss}</mss:URI></mss:MSSP_ID></mss:MSSP_Info>
        <mss:MobileUser><mss:MSISDN>${xmlEscape(a.msisdn)}</mss:MSISDN></mss:MobileUser>
      </mss:MSS_RegistrationReq>
    </mss:MSS_Registration>
  </soap:Body>
</soap:Envelope>`;
}

function parseStatusResp(xml: string): MssStatusResult {
	const doc = parseSoap(xml);
	const statusCode = firstAttr(doc, NS.mss, "StatusCode", "Value") ?? "";
	const statusMessage = firstText(doc, NS.mss, "StatusMessage") ?? "";
	const sigB64 = firstText(doc, NS.mss, "Base64Signature") ?? firstText(doc, NS.mss, "MSS_Signature");
	return {
		statusCode,
		statusMessage,
		...(sigB64 ? { signature: new Uint8Array(Buffer.from(sigB64.trim(), "base64")) } : {}),
	};
}

function parseProfileQueryResp(xml: string): MssProfileQueryResult {
	const doc = parseSoap(xml);
	const profileNodes = doc.getElementsByTagNameNS(NS.mss, "SignatureProfile");
	const profiles: string[] = [];
	for (let i = 0; i < profileNodes.length; i++) {
		const n = profileNodes.item(i);
		if (!n) continue;
		const text = firstText(n, NS.mss, "mssURI") ?? n.textContent ?? "";
		const uri = text.trim();
		if (uri) profiles.push(uri);
	}
	return {
		msspTransId: firstText(doc, NS.mss, "MSSP_TransID") ?? "",
		...(firstAttr(doc, NS.mss, "StatusCode", "Value") && { statusCode: firstAttr(doc, NS.mss, "StatusCode", "Value")! }),
		...(firstText(doc, NS.mss, "StatusMessage") && { statusMessage: firstText(doc, NS.mss, "StatusMessage")! }),
		profiles,
	};
}

function parseRegistrationResp(xml: string): MssSignerCertResult {
	const doc = parseSoap(xml);
	const certB64 = firstText(doc, NS.mss, "X509Certificate") ?? "";
	const certUri = firstText(doc, NS.mss, "CertificateURI") ?? undefined;
	return {
		msspTransId: firstText(doc, NS.mss, "MSSP_TransID") ?? "",
		...(firstAttr(doc, NS.mss, "StatusCode", "Value") && { statusCode: firstAttr(doc, NS.mss, "StatusCode", "Value")! }),
		...(firstText(doc, NS.mss, "StatusMessage") && { statusMessage: firstText(doc, NS.mss, "StatusMessage")! }),
		...(certB64.trim() && { certificate: new Uint8Array(Buffer.from(certB64.trim(), "base64")) }),
		...(certUri && { certificateUri: certUri }),
	};
}

// ---- SOAP envelope builder ----

type ReqArgs = {
	apId: string; apPwd: string; apTransId: string; instant: string;
	msisdn: string; dataToBeSigned: Uint8Array; dataMimeType: string;
	dataToBeDisplayed?: string; signatureProfile: string; mssFormat: string;
	messagingMode: MessagingMode; timeOutSec?: number;
};

function buildSignatureReq(a: ReqArgs): string {
	const dataB64 = Buffer.from(a.dataToBeSigned).toString("base64");
	const displayTag = a.dataToBeDisplayed === undefined
		? ""
		: `\n      <mss:DataToBeDisplayed MimeType="text/plain" Encoding="UTF-8">${xmlEscape(a.dataToBeDisplayed)}</mss:DataToBeDisplayed>`;
	const timeOutTag = a.timeOutSec === undefined ? "" : `\n      <mss:TimeOut>${a.timeOutSec}</mss:TimeOut>`;
	return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="${NS.soap}" xmlns:mss="${NS.mss}">
  <soap:Body>
    <mss:MSS_Signature>
      <mss:MSS_SignatureReq MajorVersion="1" MinorVersion="1" MessagingMode="${a.messagingMode}"${timeOutTag ? "" : ""}>
        <mss:AP_Info AP_ID="${xmlEscape(a.apId)}" AP_TransID="${xmlEscape(a.apTransId)}" AP_PWD="${xmlEscape(a.apPwd)}" Instant="${a.instant}"/>
        <mss:MSSP_Info><mss:MSSP_ID><mss:URI>${NS.mss}</mss:URI></mss:MSSP_ID></mss:MSSP_Info>${timeOutTag}
        <mss:MobileUser><mss:MSISDN>${xmlEscape(a.msisdn)}</mss:MSISDN></mss:MobileUser>
        <mss:DataToBeSigned MimeType="${a.dataMimeType}" Encoding="base64">${dataB64}</mss:DataToBeSigned>${displayTag}
        <mss:SignatureProfile><mss:mssURI>${xmlEscape(a.signatureProfile)}</mss:mssURI></mss:SignatureProfile>
        <mss:MSS_Format><mss:mssURI>${xmlEscape(a.mssFormat)}</mss:mssURI></mss:MSS_Format>
      </mss:MSS_SignatureReq>
    </mss:MSS_Signature>
  </soap:Body>
</soap:Envelope>`;
}

// ---- SOAP transport ----

async function postSoap(url: string, envelope: string, action: string, fetchImpl?: typeof fetch): Promise<string> {
	const f = fetchImpl ?? fetch;
	const r = await f(url, {
		method: "POST",
		headers: {
			"Content-Type": "text/xml; charset=utf-8",
			SOAPAction: `"${action}"`,
		},
		body: envelope,
	});
	const text = await r.text();
	if (!r.ok) throw new Error(`MSS: HTTP ${r.status} — ${text.slice(0, 200)}`);
	return text;
}

// ---- Response parser ----

function parseSignatureResp(xml: string): MssSignResult {
	const doc = parseSoap(xml);

	const msspTransId = firstText(doc, NS.mss, "MSSP_TransID") ?? "";
	// ETSI §5.2.2: Status/StatusCode/@Value (attribute) + Status/StatusMessage (text).
	const statusCode = firstAttr(doc, NS.mss, "StatusCode", "Value")
		?? firstText(doc, NS.mss, "StatusCode") ?? undefined;
	const statusMessage = firstText(doc, NS.mss, "StatusMessage") ?? undefined;

	const sigB64 = firstText(doc, NS.mss, "Base64Signature")
		?? firstText(doc, NS.mss, "MSS_Signature");
	if (!sigB64) throw new Error("MSS: cevapta Base64Signature/MSS_Signature bulunamadı");
	const signature = new Uint8Array(Buffer.from(sigB64.trim(), "base64"));
	return {
		signature,
		msspTransId,
		...(statusCode !== undefined && { statusCode }),
		...(statusMessage !== undefined && { statusMessage }),
	};
}

// ---- utils ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseSoap(xml: string): any {
	const doc = new DOMParser().parseFromString(xml, "text/xml");
	const fault = doc.getElementsByTagNameNS(NS.soap, "Fault").item(0);
	if (fault) throw new Error(`MSS SOAP Fault: ${textContent(fault)}`);
	return doc;
}

function xmlEscape(s: string): string {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function uuid(): string {
	const b = new Uint8Array(16);
	globalThis.crypto.getRandomValues(b);
	b[6] = (b[6]! & 0x0f) | 0x40; b[8] = (b[8]! & 0x3f) | 0x80;
	const h = Array.from(b, (x) => x.toString(16).padStart(2, "0"));
	return `${h.slice(0, 4).join("")}-${h.slice(4, 6).join("")}-${h.slice(6, 8).join("")}-${h.slice(8, 10).join("")}-${h.slice(10).join("")}`;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstText(doc: any, ns: string, local: string): string | null {
	const n = doc.getElementsByTagNameNS(ns, local).item(0);
	return n ? textContent(n) : null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstAttr(doc: any, ns: string, local: string, attr: string): string | null {
	const n = doc.getElementsByTagNameNS(ns, local).item(0);
	return n?.getAttribute(attr) ?? null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function textContent(n: any): string {
	return n?.textContent ?? "";
}
