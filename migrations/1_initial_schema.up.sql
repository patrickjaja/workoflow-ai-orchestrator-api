-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_organizations_deleted_at ON organizations(deleted_at);
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    uuid VARCHAR(100) UNIQUE,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    settings JSON,
    last_login_at TIMESTAMP,
    external_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP,
    UNIQUE(organization_id, email)
);

CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- OAuth Providers table
CREATE TABLE IF NOT EXISTS oauth_providers (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255),
    provider_type VARCHAR(50) NOT NULL CHECK (provider_type IN ('microsoft', 'atlassian', 'slack', 'google', 'github')),
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    tenant_id VARCHAR(255),
    additional_config JSONB,
    scopes TEXT[],
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP,
    UNIQUE(organization_id, provider_type)
);

CREATE INDEX IF NOT EXISTS idx_oauth_providers_organization_id ON oauth_providers(organization_id);
CREATE INDEX IF NOT EXISTS idx_oauth_providers_deleted_at ON oauth_providers(deleted_at);
CREATE INDEX IF NOT EXISTS idx_oauth_providers_enabled ON oauth_providers(enabled);

-- User Tokens table
CREATE TABLE IF NOT EXISTS user_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id BIGINT NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMP,
    scopes TEXT[],
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP,
    UNIQUE(user_id, provider_id)
);

CREATE INDEX IF NOT EXISTS idx_user_tokens_user_id ON user_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_user_tokens_provider_id ON user_tokens(provider_id);
CREATE INDEX IF NOT EXISTS idx_user_tokens_deleted_at ON user_tokens(deleted_at);
CREATE INDEX IF NOT EXISTS idx_user_tokens_expires_at ON user_tokens(expires_at) WHERE expires_at IS NOT NULL;

-- N8N Webhooks table
CREATE TABLE IF NOT EXISTS n8n_webhooks (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    webhook_url TEXT NOT NULL,
    api_key TEXT,
    headers JSONB,
    is_default BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    description TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP,
    CONSTRAINT unique_default_webhook EXCLUDE (organization_id WITH =) WHERE (is_default = true)
);

CREATE INDEX IF NOT EXISTS idx_n8n_webhooks_organization_id ON n8n_webhooks(organization_id);
CREATE INDEX IF NOT EXISTS idx_n8n_webhooks_deleted_at ON n8n_webhooks(deleted_at);
CREATE INDEX IF NOT EXISTS idx_n8n_webhooks_enabled ON n8n_webhooks(enabled);
CREATE INDEX IF NOT EXISTS idx_n8n_webhooks_is_default ON n8n_webhooks(is_default) WHERE is_default = true;

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_conversation_id VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'completed', 'failed')),
    context JSONB,
    summary TEXT,
    last_message_at TIMESTAMP,
    message_count INTEGER DEFAULT 0,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_conversations_user_id ON conversations(user_id);
CREATE INDEX IF NOT EXISTS idx_conversations_deleted_at ON conversations(deleted_at);
CREATE INDEX IF NOT EXISTS idx_conversations_status ON conversations(status);
CREATE INDEX IF NOT EXISTS idx_conversations_external_id ON conversations(external_conversation_id) WHERE external_conversation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_conversations_last_message_at ON conversations(last_message_at DESC) WHERE last_message_at IS NOT NULL;

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id BIGSERIAL PRIMARY KEY,
    conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    token_count INTEGER,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_deleted_at ON messages(deleted_at);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at DESC);

-- Update triggers for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_providers_updated_at BEFORE UPDATE ON oauth_providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_tokens_updated_at BEFORE UPDATE ON user_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_n8n_webhooks_updated_at BEFORE UPDATE ON n8n_webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversations_updated_at BEFORE UPDATE ON conversations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();