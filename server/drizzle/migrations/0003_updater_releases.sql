-- Updater feature: per-device control fields + cached release manifest.

ALTER TABLE `agents` ADD `current_version` text;
ALTER TABLE `agents` ADD `target_triple` text;
ALTER TABLE `agents` ADD `target_version` text;
ALTER TABLE `agents` ADD `update_channel` text DEFAULT 'stable' NOT NULL;
ALTER TABLE `agents` ADD `last_update_attempt_at` text;
ALTER TABLE `agents` ADD `last_update_failure` text;

CREATE TABLE `releases` (
  `version` text PRIMARY KEY NOT NULL,
  `channel` text NOT NULL,
  `published_at` text NOT NULL,
  `rollout_percent` integer DEFAULT 100 NOT NULL,
  `notes` text,
  `assets_json` text NOT NULL,
  `fetched_at` text DEFAULT (datetime('now')) NOT NULL
);
