// PKCS#11 akıllı kart ve HSM bağlantısı. Token'daki private key'le imzalama
// için graphene-pk11 üstünde ince TR-odaklı sarmalayıcı.
//
// Kullanım:
//   const { session, findSigner, close } = openPkcs11({
//     modulePath: "/Library/OpenSC/lib/opensc-pkcs11.so",
//     pin: process.env.PIN!,
//   });
//   const { certificate, privateKey } = findSigner(session, { subject: /Mali Mühür/ });
//   // sonra SignerInput: { subtle: toSubtle(privateKey, session), certificate }
//   close();
//
// MA3 karşılığı: tr.gov.tubitak.uekae.esya.api.smartcard (P11SmartCard +
// BaseSmartCard + keyfinder + pkcs11/*). Biz graphene-pk11'in üstünde
// session yönetimi ve sertifika eşleştirme sağlıyoruz.

import * as graphene from "graphene-pk11";

export type Pkcs11Options = {
	/** libsofthsm2.so, opensc-pkcs11.so, AKIS PKCS#11 .so/.dll yolu */
	modulePath: string;
	/** Token PIN (CKU_USER) */
	pin: string;
	/** Slot seçimi: yoksa ilk token taşıyan slot. Handle Buffer veya sayı. */
	slot?: number | Buffer;
	/** Module.load için görünür isim */
	vendor?: string;
};

export type Pkcs11Handle = {
	module: graphene.Module;
	session: graphene.Session;
	/** Logout + session close + module finalize. İdempotent. */
	close: () => void;
};

export type SignerFilter = {
	/** Exact CKA_LABEL eşleşmesi */
	label?: string;
	/** Subject DN regex (örn. /CN=Ad Soyad/) */
	subject?: RegExp;
};

export type Pkcs11Signer = {
	/** X.509 DER bytes (pkijs.Certificate'e parse edilebilir) */
	certificate: Uint8Array;
	/** PKCS#11 private key handle (sign için Session.createSign'a verilir) */
	privateKey: graphene.PrivateKey;
	/** SHA-256/384/512 × RSA veya ECDSA imzalama mechanism helper */
	mechanism: graphene.MechanismType;
};

export function openPkcs11(opts: Pkcs11Options): Pkcs11Handle {
	const module = graphene.Module.load(opts.modulePath, opts.vendor ?? "pkcs11");
	module.initialize();
	const slots = module.getSlots(true);
	if (slots.length === 0) {
		module.finalize();
		throw new Error("pkcs11: token taşıyan slot yok");
	}
	let slot: graphene.Slot;
	if (opts.slot !== undefined) {
		slot = typeof opts.slot === "number"
			? slots.items(opts.slot)
			: findSlotByHandle(slots, opts.slot);
	} else {
		slot = slots.items(0);
	}
	const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
	session.login(opts.pin);

	let closed = false;
	const close = (): void => {
		if (closed) return;
		closed = true;
		try { session.logout(); } catch { /* ignore */ }
		try { session.close(); } catch { /* ignore */ }
		try { module.finalize(); } catch { /* ignore */ }
	};
	return { module, session, close };
}

export function findSigner(session: graphene.Session, filter: SignerFilter = {}): Pkcs11Signer {
	// Private key: sign amaçlı, filter.label eşleşiyorsa ona göre.
	const privTemplate: graphene.ITemplate = { class: graphene.ObjectClass.PRIVATE_KEY, sign: true };
	if (filter.label !== undefined) privTemplate.label = filter.label;
	const privs = session.find(privTemplate);
	if (privs.length === 0) throw new Error("pkcs11: imzalayabilen private key yok");
	const priv = privs.items(0).toType<graphene.PrivateKey>();

	// Eşleşen sertifika: aynı CKA_ID. X509Certificate.value = DER bytes.
	const certs = session.find({ class: graphene.ObjectClass.CERTIFICATE, id: priv.id });
	if (certs.length === 0) throw new Error("pkcs11: eşleşen sertifika (CKA_ID) yok");
	let chosenCert = certs.items(0).toType<graphene.X509Certificate>();
	if (filter.subject) {
		// subject regex'e uyan ilk cert
		for (let i = 0; i < certs.length; i++) {
			const c = certs.items(i).toType<graphene.X509Certificate>();
			// subject Buffer DER-encoded Name; okunabilir CN extraction cert-level iş;
			// PFX'tekine paralel şekilde DER bytes üzerinden test yapmak basit değil.
			// Pragmatik: subject DER'in latin1 temsilinde regex match.
			const dn = c.subject.toString("latin1");
			if (filter.subject.test(dn)) { chosenCert = c; break; }
		}
	}

	// Mechanism: key tipine göre (RSA_PKCS/SHA256_RSA_PKCS; ECDSA/ECDSA_SHA256).
	const mechanism = pickMechanism(priv);
	return { certificate: new Uint8Array(chosenCert.value), privateKey: priv, mechanism };
}

export function pkcs11Sign(
	session: graphene.Session,
	signer: Pkcs11Signer,
	data: Uint8Array,
): Uint8Array {
	const sign = session.createSign(signer.mechanism, signer.privateKey);
	return new Uint8Array(sign.once(Buffer.from(data)));
}

function findSlotByHandle(slots: graphene.SlotCollection, handle: Buffer): graphene.Slot {
	for (let i = 0; i < slots.length; i++) {
		const s = slots.items(i);
		if (Buffer.compare(s.handle, handle) === 0) return s;
	}
	throw new Error(`pkcs11: slot handle eşleşmedi: ${handle.toString("hex")}`);
}

function pickMechanism(key: graphene.PrivateKey): graphene.MechanismType {
	// RSA → CKM_SHA256_RSA_PKCS (hash + sign), EC → CKM_ECDSA_SHA256.
	// KeyType değeri pkcs11 spec'inde: RSA=0, DSA=1, EC=3.
	// graphene KeyType enum'u kullan.
	if (key.type === graphene.KeyType.RSA) return graphene.MechanismEnum.SHA256_RSA_PKCS;
	if (key.type === graphene.KeyType.ECDSA) return graphene.MechanismEnum.ECDSA_SHA256;
	throw new Error(`pkcs11: desteklenmeyen anahtar tipi: ${key.type}`);
}
