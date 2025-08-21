-- Drop triggers
DROP TRIGGER IF EXISTS update_conversations_updated_at ON conversations;
DROP TRIGGER IF EXISTS update_n8n_webhooks_updated_at ON n8n_webhooks;
DROP TRIGGER IF EXISTS update_user_tokens_updated_at ON user_tokens;
DROP TRIGGER IF EXISTS update_oauth_providers_updated_at ON oauth_providers;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse order of dependencies
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS conversations;
DROP TABLE IF EXISTS n8n_webhooks;
DROP TABLE IF EXISTS user_tokens;
DROP TABLE IF EXISTS oauth_providers;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;