import { isClientSecretReferenceId, TaskSyncerSettings } from "./settings-model";
import type { SecretStore } from "./secret-store";

type CredentialKey = "clientId" | "clientSecretId" | "redirectUrl";

export interface SettingsEffects {
	logout(): Promise<void>;

	rebuild(): Promise<void>;
	save(): Promise<void>;
	refresh(): Promise<void>;
}

export async function changeProviderCredential(
	settings: TaskSyncerSettings,
	key: CredentialKey,
	value: string,
	effects: SettingsEffects,
): Promise<void> {
	if (key === "clientSecretId" && !isClientSecretReferenceId(value)) {
		throw new Error("Client secret reference must be a SecretStorage ID with lowercase letters, digits, and dashes, and cannot be an internal token-cache or legacy-conflict ID.");
	}
	await effects.logout();
	settings.providers[settings.provider][key] = value;
	await effects.rebuild();
	await effects.save();
	await effects.refresh();
}

export async function changeProviderClientSecret(
	settings: TaskSyncerSettings,
	secrets: SecretStore,
	value: string,
	effects: SettingsEffects,
): Promise<void> {
	const secret = value.trim();
	if (!secret) throw new Error("Client secret cannot be empty.");
	const id = settings.providers[settings.provider].clientSecretId;
	if (!isClientSecretReferenceId(id)) {
		throw new Error("Client secret reference must be a SecretStorage ID with lowercase letters, digits, and dashes, and cannot be an internal token-cache or legacy-conflict ID.");
	}
	secrets.write(id, secret);
	if (secrets.read(id) !== secret) throw new Error("Could not verify saved client secret in SecretStorage.");
	await effects.logout();
	await effects.rebuild();
	await effects.save();
	await effects.refresh();
}

export async function changeTimeZone(
	settings: TaskSyncerSettings,
	value: string,
	effects: SettingsEffects,
): Promise<void> {
	try { new Intl.DateTimeFormat("en", { timeZone: value }).format(); }
	catch { throw new Error(`Invalid IANA time zone: ${value}`); }
	settings.timeZone = value;
	await effects.rebuild();
	await effects.save();
	await effects.refresh();
}
