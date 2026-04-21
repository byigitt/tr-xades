// PAdES-B-B imzalayıcı. ETSI EN 319 142-1 §5.3 baseline profili.
//
// Akış:
//   1. `addSignaturePlaceholder()` ile placeholder /Sig dict + AcroForm ekle,
//      /ByteRange placeholder'ını asıl değerlerle rewrite et
//   2. ByteRange dilimlerini çıkart (/Contents placeholder hariç)
//   3. `cadesSign({data:<byteRange>, contentIncluded:false, ...})` →
//      CAdES-BES detached CMS (eContent yok; messageDigest = SHA-256(data))
//   4. CMS byte'larını /Contents hex placeholder'ına uzunluk koruyarak yaz
//
// Spec: /SubFilter /ETSI.CAdES.detached; CMS signedAttrs = contentType +
// messageDigest + signingCertV2 (CAdES ile aynı), opsiyonel policy + commitment.

import { cadesSign } from "./cades-sign.ts";
import type { HashAlg, SignatureAlg } from "./crypto.ts";
import {
	addSignaturePlaceholder,
	extractByteRangeBytes,
	readByteRange,
	spliceSignature,
	type PlaceholderOptions,
} from "./pades-core.ts";
import { addVisibleAppearance, type VisibleSignatureOptions } from "./pades-visible.ts";
import type { Policy, Profile } from "./policy.ts";
import type { SignerInput } from "./sign.ts";
import type { CommitmentType } from "./signed-properties.ts";

export type PadesSignOptions = {
	pdf: Uint8Array;
	signer: SignerInput;
	reason?: string;
	location?: string;
	contactInfo?: string;
	signerName?: string;
	/** /Contents placeholder boyutu (bayt). Default 16384 — RSA-2048 + OCSP için yeter. */
	signatureSize?: number;
	digestAlgorithm?: HashAlg;
	signatureAlgorithm?: SignatureAlg;
	signingTime?: Date | null;
	policy?: Profile | Policy;
	commitmentType?: CommitmentType;
	/** Görünür imza — sayfa, dikdörtgen, metin. EN 319 142-1 §5.3. */
	visibleSignature?: VisibleSignatureOptions;
};

export async function padesSign(opts: PadesSignOptions): Promise<Uint8Array> {
	const placeholder: PlaceholderOptions = {
		...(opts.reason !== undefined && { reason: opts.reason }),
		...(opts.location !== undefined && { location: opts.location }),
		...(opts.contactInfo !== undefined && { contactInfo: opts.contactInfo }),
		...(opts.signerName !== undefined && { signerName: opts.signerName }),
		...(opts.signatureSize !== undefined && { signatureSize: opts.signatureSize }),
	};
	let pdfWithPlaceholder = addSignaturePlaceholder(opts.pdf, placeholder);
	if (opts.visibleSignature) {
		pdfWithPlaceholder = addVisibleAppearance(pdfWithPlaceholder, opts.visibleSignature);
	}
	const byteRange = readByteRange(pdfWithPlaceholder);
	const dataToSign = extractByteRangeBytes(pdfWithPlaceholder, byteRange);

	const cms = await cadesSign({
		data: dataToSign,
		signer: opts.signer,
		contentIncluded: false,
		...(opts.digestAlgorithm !== undefined && { digestAlgorithm: opts.digestAlgorithm }),
		...(opts.signatureAlgorithm !== undefined && { signatureAlgorithm: opts.signatureAlgorithm }),
		...(opts.signingTime !== undefined && { signingTime: opts.signingTime }),
		...(opts.policy !== undefined && { policy: opts.policy }),
		...(opts.commitmentType !== undefined && { commitmentType: opts.commitmentType }),
	});

	return spliceSignature(pdfWithPlaceholder, cms);
}
