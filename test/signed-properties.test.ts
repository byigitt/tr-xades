import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { DOMImplementation, XMLSerializer } from "@xmldom/xmldom";
import { buildSignedProperties } from "../src/signed-properties.ts";
import { loadPfx } from "../src/pfx.ts";

const FIXTURE = join(import.meta.dirname, "..", "reference", "fixtures", "test.p12");
const has = (() => { try { readFileSync(FIXTURE); return true; } catch { return false; } })();

test("buildSignedProperties — minimum opts matches MA3 structure",
	{ skip: !has && "run reference/run.sh" },
	async () => {
		const b = await loadPfx(new Uint8Array(readFileSync(FIXTURE)), "testpass");
		const doc = new DOMImplementation().createDocument(null, null) as unknown as Document;
		const { element, id } = await buildSignedProperties(doc, {
			certificate: b.certificate,
			dataObjectFormat: { referenceId: "R1", mimeType: "text/xml" },
		});
		doc.appendChild(element as unknown as Node);

		assert.match(id, /^Signed-Properties-Id-/);
		const xml = new XMLSerializer().serializeToString(element as unknown as Node);
		assert.match(xml, /<xades:SignedProperties\b[^>]*Id="Signed-Properties-Id-/);
		assert.match(xml, /<xades:SigningCertificate>/);
		assert.match(xml, /<xades:CertDigest>/);
		assert.match(xml, /<ds:DigestMethod\b[^>]*Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmlenc#sha256"/);
		assert.match(xml, /<ds:X509IssuerName[^>]*>CN=Test Signer,O=tr-xades test,C=TR<\/ds:X509IssuerName>/);
		// MA3 fixture had serial 5586002494688706913 (= 0x4D8577AC4A5DC161).
		assert.match(xml, /<ds:X509SerialNumber[^>]*>\d+<\/ds:X509SerialNumber>/);
		assert.match(xml, /<xades:DataObjectFormat\b[^>]*ObjectReference="#R1">/);
		// BES default: no SigningTime, no policy.
		assert.doesNotMatch(xml, /<xades:SigningTime/);
		assert.doesNotMatch(xml, /<xades:SignaturePolicyIdentifier/);
	});

test("buildSignedProperties — full opts emits all branches",
	{ skip: !has && "run reference/run.sh" },
	async () => {
		const b = await loadPfx(new Uint8Array(readFileSync(FIXTURE)), "testpass");
		const doc = new DOMImplementation().createDocument(null, null) as unknown as Document;
		const { element } = await buildSignedProperties(doc, {
			certificate: b.certificate,
			signingTime: new Date("2026-04-20T10:00:00Z"),
			productionPlace: { city: "Ankara", country: "TR" },
			signerRole: { claimed: ["CFO", "Yetkili İmza"] },
			commitmentType: "proof-of-approval",
			dataObjectFormat: { referenceId: "R1", mimeType: "text/xml" },
			policy: {
				oid: "2.16.792.1.61.0.1.5070.3.2.1", // TR P3
				digest: new Uint8Array(32), // stub hash
				digestAlgorithm: "SHA-256",
				uri: "https://kamusm.bilgem.tubitak.gov.tr/...",
			},
		});
		const xml = new XMLSerializer().serializeToString(element as unknown as Node);
		assert.match(xml, /<xades:SigningTime>2026-04-20T10:00:00\.000Z<\/xades:SigningTime>/);
		assert.match(xml, /<xades:SignaturePolicyIdentifier>/);
		assert.match(xml, /urn:oid:2\.16\.792\.1\.61\.0\.1\.5070\.3\.2\.1/);
		assert.match(xml, /<xades:SignatureProductionPlace>/);
		assert.match(xml, /<xades:City>Ankara<\/xades:City>/);
		assert.match(xml, /<xades:ClaimedRole>CFO<\/xades:ClaimedRole>/);
		assert.match(xml, /<xades:ClaimedRole>Yetkili İmza<\/xades:ClaimedRole>/);
		assert.match(xml, /<xades:CommitmentTypeIndication>/);
		assert.match(xml, /urn:oid:1\.2\.840\.113549\.1\.9\.16\.6\.5/); // proof-of-approval
	});
