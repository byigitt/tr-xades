// MSS (Mobil İmza) — mock SOAP fetch ile offline test. Gerçek operator
// endpoint testi kimlik bilgisi ister; opt-in yapmadım (kapsam dışı).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mssPoll, mssProfileQuery, mssSign, mssSignerCert, mssStatus } from "../src/mss.ts";

const MSS_NS = "http://uri.etsi.org/TS102204/v1.1.2#";

function wrapResp(body: string): string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mss="${MSS_NS}">
  <soap:Body>${body}</soap:Body>
</soap:Envelope>`;
}

function sigResp(statusCode: string, statusMessage: string, sigB64?: string): string {
	const sigTag = sigB64 ? `<mss:MSS_Signature>${sigB64}</mss:MSS_Signature>` : "";
	return wrapResp(`
    <mss:MSS_SignatureResp MajorVersion="1" MinorVersion="1">
      <mss:AP_Info AP_ID="ap" AP_TransID="t" Instant="2026-04-21T12:00:00Z"/>
      <mss:MSSP_Info><mss:MSSP_ID><mss:URI>${MSS_NS}</mss:URI></mss:MSSP_ID></mss:MSSP_Info>
      <mss:MSSP_TransID>TR-12345</mss:MSSP_TransID>
      <mss:Status><mss:StatusCode Value="${statusCode}"/><mss:StatusMessage>${statusMessage}</mss:StatusMessage></mss:Status>
      ${sigTag}
    </mss:MSS_SignatureResp>`);
}

function statusResp(code: string, msg: string, sigB64?: string): string {
	const sigTag = sigB64 ? `<mss:MSS_Signature>${sigB64}</mss:MSS_Signature>` : "";
	return wrapResp(`
    <mss:MSS_StatusResp MajorVersion="1" MinorVersion="1">
      <mss:Status><mss:StatusCode Value="${code}"/><mss:StatusMessage>${msg}</mss:StatusMessage></mss:Status>
      ${sigTag}
    </mss:MSS_StatusResp>`);
}

function profileResp(code: string, msg: string, profiles: string[]): string {
	return wrapResp(`
    <mss:MSS_ProfileResp MajorVersion="1" MinorVersion="1">
      <mss:MSSP_TransID>TR-PROFILE-1</mss:MSSP_TransID>
      ${profiles.map((p) => `<mss:SignatureProfile><mss:mssURI>${p}</mss:mssURI></mss:SignatureProfile>`).join("")}
      <mss:Status><mss:StatusCode Value="${code}"/><mss:StatusMessage>${msg}</mss:StatusMessage></mss:Status>
    </mss:MSS_ProfileResp>`);
}

function registrationResp(code: string, msg: string, certB64?: string, certUri?: string): string {
	return wrapResp(`
    <mss:MSS_RegistrationResp MajorVersion="1" MinorVersion="1">
      <mss:MSSP_TransID>TR-REG-1</mss:MSSP_TransID>
      ${certUri ? `<mss:CertificateURI>${certUri}</mss:CertificateURI>` : ""}
      ${certB64 ? `<mss:X509Certificate>${certB64}</mss:X509Certificate>` : ""}
      <mss:Status><mss:StatusCode Value="${code}"/><mss:StatusMessage>${msg}</mss:StatusMessage></mss:Status>
    </mss:MSS_RegistrationResp>`);
}

test("mssSign — synch mod envelope doğru + response parse", async () => {
	let seen: { url: string; body: string; action: string | null } | null = null;
	const fakeFetch: typeof fetch = async (input, init): Promise<Response> => {
		const url = typeof input === "string" ? input : (input as URL).toString();
		const body = init?.body as string;
		const headers = (init?.headers ?? {}) as Record<string, string>;
		seen = { url, body, action: headers.SOAPAction ?? null };
		return new Response(sigResp("502", "Signature OK", "SGVsbG8=" /* "Hello" */), {
			status: 200, headers: { "Content-Type": "text/xml" },
		});
	};

	const r = await mssSign({
		serviceUrl: "https://mssp.test/MSS_Signature",
		apId: "tr-esign", apPwd: "secret",
		msisdn: "905551234567",
		dataToBeSigned: new TextEncoder().encode("merhaba"),
		dataToBeDisplayed: "Onay verir misiniz?",
		fetch: fakeFetch,
	});

	assert.equal(r.msspTransId, "TR-12345");
	assert.equal(r.statusCode, "502");
	assert.equal(r.statusMessage, "Signature OK");
	assert.equal(Buffer.from(r.signature).toString(), "Hello");

	// Envelope content sanity checks
	assert.ok(seen, "fetch çağrılmadı");
	const s = seen as { url: string; body: string; action: string | null };
	assert.equal(s.url, "https://mssp.test/MSS_Signature");
	assert.equal(s.action, "\"MSS_Signature\"");
	assert.match(s.body, /MSS_SignatureReq/);
	assert.match(s.body, /AP_ID="tr-esign"/);
	assert.match(s.body, /AP_PWD="secret"/);
	assert.match(s.body, /<mss:MSISDN>905551234567<\/mss:MSISDN>/);
	assert.match(s.body, /MessagingMode="synch"/);
	// dataToBeSigned base64("merhaba") = "bWVyaGFiYQ=="
	assert.match(s.body, /<mss:DataToBeSigned[^>]*>bWVyaGFiYQ==<\/mss:DataToBeSigned>/);
	assert.match(s.body, /DataToBeDisplayed/);
	assert.match(s.body, /Onay verir misiniz\?/);
});

test("mssProfileQuery — profil listesi parse + envelope doğru", async () => {
	let seen: { url: string; body: string; action: string | null } | null = null;
	const fakeFetch: typeof fetch = async (input, init): Promise<Response> => {
		const url = typeof input === "string" ? input : (input as URL).toString();
		const body = init?.body as string;
		const headers = (init?.headers ?? {}) as Record<string, string>;
		seen = { url, body, action: headers.SOAPAction ?? null };
		return new Response(profileResp("100", "OK", [
			"http://uri.etsi.org/TS102204/v1.1.2#signature-profile",
			"http://example.test/profile/qualified",
		]), { status: 200, headers: { "Content-Type": "text/xml" } });
	};

	const r = await mssProfileQuery({
		serviceUrl: "https://mssp.test/MSS_ProfileQuery",
		apId: "tr-esign", apPwd: "secret", msisdn: "905551234567", fetch: fakeFetch,
	});

	assert.equal(r.msspTransId, "TR-PROFILE-1");
	assert.equal(r.statusCode, "100");
	assert.equal(r.statusMessage, "OK");
	assert.deepEqual(r.profiles, [
		"http://uri.etsi.org/TS102204/v1.1.2#signature-profile",
		"http://example.test/profile/qualified",
	]);
	assert.ok(seen, "fetch çağrılmadı");
	const s = seen as { url: string; body: string; action: string | null };
	assert.equal(s.url, "https://mssp.test/MSS_ProfileQuery");
	assert.equal(s.action, '"MSS_ProfileQuery"');
	assert.match(s.body, /MSS_ProfileReq/);
	assert.match(s.body, /AP_ID="tr-esign"/);
	assert.match(s.body, /AP_PWD="secret"/);
	assert.match(s.body, /<mss:MSISDN>905551234567<\/mss:MSISDN>/);
});

test("mssSignerCert — sertifika parse + envelope doğru", async () => {
	let seen: { url: string; body: string; action: string | null } | null = null;
	const fakeFetch: typeof fetch = async (input, init): Promise<Response> => {
		const url = typeof input === "string" ? input : (input as URL).toString();
		const body = init?.body as string;
		const headers = (init?.headers ?? {}) as Record<string, string>;
		seen = { url, body, action: headers.SOAPAction ?? null };
		return new Response(registrationResp(
			"100",
			"OK",
			"QUJDREVGRw==",
			"https://mssp.test/cert/123",
		), { status: 200, headers: { "Content-Type": "text/xml" } });
	};

	const r = await mssSignerCert({
		serviceUrl: "https://mssp.test/MSS_Registration",
		apId: "tr-esign", apPwd: "secret", msisdn: "905551234567", fetch: fakeFetch,
	});

	assert.equal(r.msspTransId, "TR-REG-1");
	assert.equal(r.statusCode, "100");
	assert.equal(r.statusMessage, "OK");
	assert.equal(Buffer.from(r.certificate!).toString(), "ABCDEFG");
	assert.equal(r.certificateUri, "https://mssp.test/cert/123");
	assert.ok(seen, "fetch çağrılmadı");
	const s = seen as { url: string; body: string; action: string | null };
	assert.equal(s.url, "https://mssp.test/MSS_Registration");
	assert.equal(s.action, '"MSS_Registration"');
	assert.match(s.body, /MSS_RegistrationReq/);
	assert.match(s.body, /AP_ID="tr-esign"/);
	assert.match(s.body, /AP_PWD="secret"/);
	assert.match(s.body, /<mss:MSISDN>905551234567<\/mss:MSISDN>/);
});

test("mssSign — SOAP Fault reddi", async () => {
	const fakeFetch: typeof fetch = async () => new Response(wrapResp(
		`<soap:Fault xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <faultcode>Client</faultcode><faultstring>bad AP_ID</faultstring></soap:Fault>`,
	), { status: 500 });
	await assert.rejects(() => mssSign({
		serviceUrl: "x", apId: "a", apPwd: "p", msisdn: "0",
		dataToBeSigned: new Uint8Array(),
		fetch: fakeFetch,
	}));
});

test("mssStatus — tek sorgu in-progress", async () => {
	const fakeFetch: typeof fetch = async () =>
		new Response(statusResp("500", "signature in progress"), { status: 200 });
	const r = await mssStatus({
		serviceUrl: "https://mssp.test/MSS_StatusQuery",
		apId: "ap", apPwd: "pw", msspTransId: "TR-X",
		fetch: fakeFetch,
	});
	assert.equal(r.statusCode, "500");
	assert.equal(r.signature, undefined);
});

test("mssPoll — in-progress → OK + signature", async () => {
	let calls = 0;
	const fakeFetch: typeof fetch = async () => {
		calls++;
		return new Response(
			calls < 3 ? statusResp("500", "in progress") : statusResp("502", "OK", "QUJDRA==" /* "ABCD" */),
			{ status: 200 },
		);
	};
	const r = await mssPoll({
		serviceUrl: "x", apId: "a", apPwd: "p", msspTransId: "t",
		intervalMs: 5, timeoutMs: 5000, fetch: fakeFetch,
	});
	assert.equal(calls, 3);
	assert.equal(r.statusCode, "502");
	assert.equal(r.signature?.byteLength, 4);
	assert.equal(Buffer.from(r.signature!).toString(), "ABCD");
});

test("mssPoll — timeout throw", async () => {
	const fakeFetch: typeof fetch = async () =>
		new Response(statusResp("500", "stuck"), { status: 200 });
	await assert.rejects(
		() => mssPoll({
			serviceUrl: "x", apId: "a", apPwd: "p", msspTransId: "t",
			intervalMs: 5, timeoutMs: 20, fetch: fakeFetch,
		}),
		/timeout/,
	);
});
