CREATE TABLE `admin_api_keys` (
	`key_hash` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`label` text,
	`created_at` text DEFAULT (datetime('now')) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `agents` (
	`agent_id` text PRIMARY KEY NOT NULL,
	`org_id` text NOT NULL,
	`public_key` text NOT NULL,
	`key_id` text NOT NULL,
	`hostname` text,
	`platform` text NOT NULL,
	`platform_version` text,
	`device_id` text,
	`status` text DEFAULT 'active' NOT NULL,
	`enrolled_at` text DEFAULT (datetime('now')) NOT NULL,
	`last_seen_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `agents_device_id_unique` ON `agents` (`device_id`);--> statement-breakpoint
CREATE TABLE `attestations` (
	`attestation_id` text PRIMARY KEY NOT NULL,
	`agent_id` text NOT NULL,
	`device_id` text NOT NULL,
	`schema_version` text NOT NULL,
	`collected_at` text NOT NULL,
	`payload` text NOT NULL,
	`signature` text NOT NULL,
	`created_at` text DEFAULT (datetime('now')) NOT NULL,
	FOREIGN KEY (`agent_id`) REFERENCES `agents`(`agent_id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `device_checks` (
	`device_id` text NOT NULL,
	`check_key` text NOT NULL,
	`check_value` text NOT NULL,
	`observed_at` text NOT NULL,
	`source` text,
	PRIMARY KEY(`device_id`, `check_key`)
);
--> statement-breakpoint
CREATE TABLE `enrollment_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`token` text NOT NULL,
	`org_id` text NOT NULL,
	`used` integer DEFAULT 0 NOT NULL,
	`revoked` integer DEFAULT 0 NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT (datetime('now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `enrollment_tokens_token_unique` ON `enrollment_tokens` (`token`);