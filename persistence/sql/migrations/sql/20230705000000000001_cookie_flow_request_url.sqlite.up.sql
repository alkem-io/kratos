ALTER TABLE selfservice_login_flows ADD COLUMN request_url_new TEXT NOT NULL DEFAULT '';
ALTER TABLE selfservice_recovery_flows ADD COLUMN request_url_new TEXT NOT NULL DEFAULT '';
ALTER TABLE selfservice_registration_flows ADD COLUMN request_url_new TEXT NOT NULL DEFAULT '';
ALTER TABLE selfservice_settings_flows ADD COLUMN request_url_new TEXT NOT NULL DEFAULT '';
ALTER TABLE selfservice_verification_flows ADD COLUMN request_url_new TEXT NOT NULL DEFAULT '';

UPDATE selfservice_login_flows SET request_url_new = request_url;
UPDATE selfservice_recovery_flows SET request_url_new = request_url;
UPDATE selfservice_registration_flows SET request_url_new = request_url;
UPDATE selfservice_settings_flows SET request_url_new = request_url;
UPDATE selfservice_verification_flows SET request_url_new = request_url;

ALTER TABLE selfservice_login_flows DROP COLUMN request_url;
ALTER TABLE selfservice_login_flows RENAME COLUMN request_url_new TO request_url;

ALTER TABLE selfservice_recovery_flows DROP COLUMN request_url;
ALTER TABLE selfservice_recovery_flows RENAME COLUMN request_url_new TO request_url;

ALTER TABLE selfservice_registration_flows DROP COLUMN request_url;
ALTER TABLE selfservice_registration_flows RENAME COLUMN request_url_new TO request_url;

ALTER TABLE selfservice_settings_flows DROP COLUMN request_url;
ALTER TABLE selfservice_settings_flows RENAME COLUMN request_url_new TO request_url;

ALTER TABLE selfservice_verification_flows DROP COLUMN request_url;
ALTER TABLE selfservice_verification_flows RENAME COLUMN request_url_new TO request_url;

