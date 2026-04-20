// Türk Elektronik İmza Kullanım Profilleri Rehberi v1 (BTK/Kamu SM).
// OID'ler constants.ts'te; burada profil adından {oid, digest, alg} çıkarımı.
//
// Digest: MA3 2.3.11.8 ile gelen rehber PDF'in (Elektronik_Imza_Kullanim_
// Profilleri_Rehberi.pdf) SHA-256'sı. MA3'ün bu hash'i runtime'da şifreli
// tuttuğunu biliyoruz; biz aynı PDF bayt'ları üstünden bağımsız hesapladık.
// Farklı policy-doc sürümü için kullanıcı trPolicy() yerine kendi
// policy objesini doğrudan verebilir.

import { TR_POLICY_OID } from "./constants.ts";
import type { HashAlg } from "./crypto.ts";

export type Profile = keyof typeof TR_POLICY_OID; // "P2" | "P3" | "P4"

export type Policy = {
	oid: string;
	digest: Uint8Array;
	digestAlgorithm: HashAlg;
	uri?: string;
};

// SHA-256 of Elektronik_Imza_Kullanim_Profilleri_Rehberi.pdf (TR v1, 2014).
const TR_POLICY_DOC_SHA256 = Uint8Array.from(
	"ff39bd29463383f69b2052ac47439e06ce7c3b8646e888b6e5ae3e46ba08117a"
		.match(/.{2}/g)!
		.map((h) => parseInt(h, 16)),
);

export function trPolicy(profile: Profile): Policy {
	return {
		oid: TR_POLICY_OID[profile],
		digest: TR_POLICY_DOC_SHA256,
		digestAlgorithm: "SHA-256",
	};
}
