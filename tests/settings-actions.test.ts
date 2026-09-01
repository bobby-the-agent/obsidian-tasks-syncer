import { describe, expect, it, vi } from "vitest";
import { changeProviderClientSecret, changeProviderCredential, changeTimeZone } from "../src/settings-actions";
import { migrateSettings } from "../src/settings-model";
import { MemorySecretStore } from "../src/secret-store";

function actions() {
	return { logout: vi.fn(async () => {}), rebuild: vi.fn(async () => {}), save: vi.fn(async () => {}), refresh: vi.fn(async () => {}) };
}

describe("settings actions", () => {
	it.each(["clientId", "clientSecretId", "redirectUrl"] as const)("invalidates auth before changing %s and rebuilding", async key => {
		const settings = migrateSettings(undefined);
		const effects = actions();
		const order: string[] = [];
		effects.logout.mockImplementation(async () => { order.push("logout"); });
		effects.rebuild.mockImplementation(async () => { order.push("rebuild"); });
		await changeProviderCredential(settings, key, "new-value", effects);
		expect(settings.providers.microsoft[key]).toBe("new-value");
		expect(settings.providers.microsoft).not.toHaveProperty("clientSecret");
		expect(order).toEqual(["logout", "rebuild"]);
		expect(effects.save).toHaveBeenCalledOnce();
		expect(effects.refresh).toHaveBeenCalledOnce();
	});

	it.each(["task-syncer-plugin-microsoft-token-cache", "task-syncer-plugin-microsoft-client-secret-legacy-conflict", "MixedCase"])("rejects invalid client secret reference %s before logout", async id => {
		const settings = migrateSettings(undefined);
		const effects = actions();
		await expect(changeProviderCredential(settings, "clientSecretId", id, effects)).rejects.toThrow(/client secret reference/i);
		expect(settings.providers.microsoft.clientSecretId).toBe("task-syncer-plugin-microsoft-client-secret");
		expect(effects.logout).not.toHaveBeenCalled();
		expect(effects.save).not.toHaveBeenCalled();
	});

	it("stores the selected provider client secret in SecretStorage and invalidates stale tokens", async () => {
		const settings = migrateSettings({
			provider: "ticktick",
			providers: {
				ticktick: {
					clientSecretId: "task-syncer-plugin-ticktick-client-secret",
				},
			},
		});
		const secrets = new MemorySecretStore();
		const effects = actions();
		const order: string[] = [];
		effects.logout.mockImplementation(async () => { order.push("logout"); });
		effects.rebuild.mockImplementation(async () => { order.push("rebuild"); });

		await changeProviderClientSecret(settings, secrets, "ticktick-secret", effects);

		expect(secrets.read("task-syncer-plugin-ticktick-client-secret")).toBe("ticktick-secret");
		expect(JSON.stringify(settings)).not.toContain("ticktick-secret");
		expect(order).toEqual(["logout", "rebuild"]);
		expect(effects.save).toHaveBeenCalledOnce();
		expect(effects.refresh).toHaveBeenCalledOnce();
	});

	it("rejects empty provider client secrets before mutating SecretStorage", async () => {
		const settings = migrateSettings({ version: 3, provider: "ticktick", providers: {} });
		const secrets = new MemorySecretStore();
		const effects = actions();

		await expect(changeProviderClientSecret(settings, secrets, "  ", effects)).rejects.toThrow(/client secret/i);

		expect(secrets.read("task-syncer-plugin-ticktick-client-secret")).toBeNull();
		expect(effects.logout).not.toHaveBeenCalled();
		expect(effects.save).not.toHaveBeenCalled();
	});

	it("rejects invalid provider client secret IDs before mutating SecretStorage", async () => {
		const settings = migrateSettings({ version: 3, provider: "ticktick", providers: {} });
		settings.providers.ticktick.clientSecretId = "task-syncer-plugin-ticktick-token-cache";
		const secrets = new MemorySecretStore();
		const effects = actions();

		await expect(changeProviderClientSecret(settings, secrets, "ticktick-secret", effects)).rejects.toThrow(/client secret reference/i);

		expect(secrets.read("task-syncer-plugin-ticktick-token-cache")).toBeNull();
		expect(effects.logout).not.toHaveBeenCalled();
		expect(effects.save).not.toHaveBeenCalled();
	});

	it("rebuilds for a timezone change without logging out", async () => {
		const settings = migrateSettings(undefined);
		const effects = actions();
		await changeTimeZone(settings, "America/Toronto", effects);
		expect(settings.timeZone).toBe("America/Toronto");
		expect(effects.logout).not.toHaveBeenCalled();
		expect(effects.rebuild).toHaveBeenCalledOnce();
	});

	it("rejects an invalid timezone before changing or saving settings", async () => {
		const settings = migrateSettings(undefined);
		const original = settings.timeZone;
		const effects = actions();
		await expect(changeTimeZone(settings, "Not/AZone", effects)).rejects.toThrow(/time zone/i);
		expect(settings.timeZone).toBe(original);
		expect(effects.rebuild).not.toHaveBeenCalled();
		expect(effects.save).not.toHaveBeenCalled();
		expect(effects.refresh).not.toHaveBeenCalled();
	});
});
