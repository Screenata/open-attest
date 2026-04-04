ALTER TABLE `enrollment_tokens` ADD `max_uses` integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE `enrollment_tokens` ADD `use_count` integer DEFAULT 0 NOT NULL;