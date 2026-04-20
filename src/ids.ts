// Element ID generator. Mirrors MA3's `{Role}-Id-{uuid}` pattern so fixtures
// stay visually close. The ID space is per-signature; callers produce one ID
// per element role (Signature, Reference, SignedProperties, Object, …).

export function makeId(role: string): string {
	return `${role}-Id-${globalThis.crypto.randomUUID()}`;
}
