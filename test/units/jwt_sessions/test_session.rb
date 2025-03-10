# frozen_string_literal: true

require "minitest/autorun"
require "jwt_sessions"

class TestSession < Minitest::Test
  attr_reader :session, :payload, :tokens
  LOGIN_KEYS = %i[access access_expires_at csrf refresh refresh_expires_at].freeze
  REFRESH_KEYS = %i[access access_expires_at csrf].freeze

  def setup
    JWTSessions.encryption_key = "encrypted"
    @payload = { test: "secret" }
    @session = JWTSessions::Session.new(payload: payload)
    @tokens = session.login
  end

  def teardown
    redis = RedisClient.new
    keys = redis.call("KEYS", "jwt_*")
    keys.each { |k| redis.call("DEL", k) }
  end

  def test_login
    decoded_access = JWTSessions::Token.decode(tokens[:access]).first
    assert_equal LOGIN_KEYS, tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
  end

  def test_login_with_custom_exp
    @new_session = JWTSessions::Session.new(
      payload: payload,
      access_exp: 18000, # 5 hours in seconds
      refresh_exp: 18000
    )
    assert_equal false, tokens[:refresh_expires_at] == tokens[:access_expires_at]
    new_tokens = @new_session.login
    assert_equal LOGIN_KEYS, new_tokens.keys.sort
    assert_equal new_tokens[:refresh_expires_at], new_tokens[:access_expires_at]
  end

  def test_refresh
    refreshed_tokens = session.refresh(tokens[:refresh])
    decoded_access = JWTSessions::Token.decode(refreshed_tokens[:access]).first
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
  end

  def test_refresh_with_custom_exp
    @new_session = JWTSessions::Session.new(
      payload: payload,
      access_exp: 18000, # 5 hours in seconds
      refresh_exp: 18000
    )
    new_tokens = @new_session.login
    refreshed_tokens = @new_session.refresh(new_tokens[:refresh])
    assert_equal LOGIN_KEYS, new_tokens.keys.sort
    assert_equal false, refreshed_tokens[:refresh_expires_at] == new_tokens[:refresh_expires_at]
  end

  def test_refresh_expired
    JWTSessions.refresh_exp_time = 0
    session = JWTSessions::Session.new(payload: payload)
    tokens = session.login
    JWTSessions.refresh_exp_time = 604800

    assert_raises JWTSessions::Errors::ClaimsVerification do
      session.refresh(tokens[:refresh])
    end
  end

  def test_refresh_with_namespace
    @new_session = JWTSessions::Session.new(
      payload: payload,
      namespace: "custom-namespace"
    )
    new_tokens = @new_session.login
    refreshed_tokens = @new_session.refresh(new_tokens[:refresh])
    decoded_access = JWTSessions::Token.decode(refreshed_tokens[:access]).first
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
  end

  def test_refresh_by_access_payload
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    access1 = session.instance_variable_get("@_access")
    sleep(1)
    refreshed_tokens = session.refresh_by_access_payload
    access2 = session.instance_variable_get("@_access")
    decoded_access = JWTSessions::Token.decode(refreshed_tokens[:access]).first
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
    assert_equal session.instance_variable_get("@_refresh").uid, decoded_access["ruid"]
    assert_equal access2.expiration > access1.expiration, true
  end

  def test_refresh_by_access_payload_expired
    JWTSessions.access_exp_time = 0
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    refreshed_tokens = session.refresh_by_access_payload
    decoded_access = JWTSessions::Token.decode!(refreshed_tokens[:access]).first
    JWTSessions.access_exp_time = 3600
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
    assert_equal session.instance_variable_get("@_refresh").uid, decoded_access["ruid"]
  end

  def test_refresh_by_access_payload_with_block_expired
    JWTSessions.access_exp_time = 0
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    refreshed_tokens = session.refresh_by_access_payload do
      raise JWTSessions::Errors::Unauthorized
    end
    decoded_access = JWTSessions::Token.decode!(refreshed_tokens[:access]).first
    JWTSessions.access_exp_time = 3600
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
    assert_equal session.instance_variable_get("@_refresh").uid, decoded_access["ruid"]
  end

  def test_refresh_by_access_payload_with_block_not_expired
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    assert_raises JWTSessions::Errors::Unauthorized do
      session.refresh_by_access_payload do
        raise JWTSessions::Errors::Unauthorized
      end
    end
  end

  def test_refresh_by_access_payload_invalid_uid
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    access1 = session.instance_variable_get("@_access")
    # should execute the code block for the cases when access UID within the refresh token
    # does not match access UID from the session payload
    session2 = JWTSessions::Session.new(payload: access1.payload, refresh_by_access_allowed: true)
    assert_raises JWTSessions::Errors::Unauthorized do
      session2.refresh_by_access_payload do
        raise JWTSessions::Errors::Unauthorized
      end
    end
  end

  def test_refresh_by_access_payload_invalid_uid_with_multiple_refreshes
    JWTSessions.access_exp_time = 0
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    sleep(1)
    JWTSessions.access_exp_time = 3600
    session.refresh_by_access_payload do
      raise JWTSessions::Errors::Unauthorized
    end
    assert_raises JWTSessions::Errors::Unauthorized do
      session.refresh_by_access_payload do
        raise JWTSessions::Errors::Unauthorized
      end
    end
  end

  def test_refresh_by_access_payload_invalid_uid_outdated_access_token
    JWTSessions.access_exp_time = 0
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    original_tokens  = session.login
    session.refresh_by_access_payload do
      raise JWTSessions::Errors::Unauthorized
    end
    decoded_access = JWTSessions::Token.decode!(original_tokens[:access]).first
    session2 = JWTSessions::Session.new(payload: decoded_access, refresh_by_access_allowed: true)
    JWTSessions.access_exp_time = 3600
    assert_raises JWTSessions::Errors::Unauthorized do
      session2.refresh_by_access_payload do
        raise JWTSessions::Errors::Unauthorized
      end
    end
  end

  def test_refresh_by_access_payload_with_valid_uid
    JWTSessions.access_exp_time = 0
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    refreshed_tokens = session.refresh_by_access_payload do
      raise JWTSessions::Errors::Unauthorized
    end

    decoded_access = JWTSessions::Token.decode!(refreshed_tokens[:access]).first
    session2 = JWTSessions::Session.new(payload: decoded_access, refresh_by_access_allowed: true)
    JWTSessions.access_exp_time = 3600

    session2.refresh_by_access_payload do
      raise JWTSessions::Errors::Unauthorized
    end

    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
    assert_equal session.instance_variable_get("@_refresh").uid, decoded_access["ruid"]
  end

  def test_refresh_renew_on_refresh
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true, renew_on_refresh: true)
    session.login
    access1 = session.instance_variable_get("@_access")
    refresh1 = session.instance_variable_get("@_refresh")
    sleep(1)
    refreshed_tokens = session.refresh_by_access_payload
    access2 = session.instance_variable_get("@_access")
    refresh2 = session.instance_variable_get("@_refresh")
    decoded_access = JWTSessions::Token.decode(refreshed_tokens[:access]).first
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
    assert_equal session.instance_variable_get("@_refresh").uid, decoded_access["ruid"]
    assert_equal access2.expiration > access1.expiration, true
    assert_equal refresh2.expiration > refresh1.expiration, true
  end

  def test_refresh_with_block_not_expired
    assert_raises JWTSessions::Errors::Unauthorized do
      session.refresh(tokens[:refresh]) do
        raise JWTSessions::Errors::Unauthorized
      end
    end
  end

  def test_refresh_with_block_expired
    JWTSessions.access_exp_time = 0
    @session = JWTSessions::Session.new(payload: payload)
    @tokens = session.login
    JWTSessions.access_exp_time = 3600
    refreshed_tokens = session.refresh(tokens[:refresh]) do
      raise JWTSessions::Errors::Unauthorized
    end
    decoded_access = JWTSessions::Token.decode(refreshed_tokens[:access]).first
    assert_equal REFRESH_KEYS, refreshed_tokens.keys.sort
    assert_equal payload[:test], decoded_access["test"]
  end

  def test_flush_by_token
    refresh_token = @session.instance_variable_get(:"@_refresh")
    uid = refresh_token.uid
    assert_equal refresh_token.token, JWTSessions::RefreshToken.find(uid, JWTSessions.token_store, nil).token

    @session.flush_by_token(refresh_token.token)

    assert_raises JWTSessions::Errors::Unauthorized do
      JWTSessions::RefreshToken.find(uid, JWTSessions.token_store, nil)
    end
  end

  def test_flush_by_access_token
    session = JWTSessions::Session.new(payload: payload, refresh_by_access_allowed: true)
    session.login
    refresh_token = session.instance_variable_get(:"@_refresh")
    uid = refresh_token.uid

    session.flush_by_access_payload

    assert_raises JWTSessions::Errors::Unauthorized do
      JWTSessions::RefreshToken.find(uid, JWTSessions.token_store, nil)
    end
  end

  def test_flush_by_uid
    refresh_token = @session.instance_variable_get(:"@_refresh")
    uid = refresh_token.uid

    @session.flush_by_uid(uid)

    assert_raises JWTSessions::Errors::Unauthorized do
      JWTSessions::RefreshToken.find(uid, JWTSessions.token_store, nil)
    end
  end

  def test_flush_namespaced
    namespace = "test_namespace"
    @session1 = JWTSessions::Session.new(payload: payload, namespace: namespace)
    @session2 = JWTSessions::Session.new(payload: payload, namespace: namespace)
    @session1.login
    @session2.login

    flushed_count = @session1.flush_namespaced

    assert_equal 2, flushed_count
    assert_raises JWTSessions::Errors::Unauthorized do
      refresh_token = @session1.instance_variable_get(:"@_refresh")
      JWTSessions::RefreshToken.find(refresh_token.uid, JWTSessions.token_store, nil)
    end

    assert_raises JWTSessions::Errors::Unauthorized do
      refresh_token = @session2.instance_variable_get(:"@_refresh")
      JWTSessions::RefreshToken.find(refresh_token.uid, JWTSessions.token_store, nil)
    end

    refresh_token = @session.instance_variable_get(:"@_refresh")
    flushed_count = @session.flush_namespaced
    assert_equal 0, flushed_count
    assert_equal refresh_token.token, JWTSessions::RefreshToken.find(refresh_token.uid, JWTSessions.token_store, nil).token
  end

  def test_flush_namespaced_access_tokens
    namespace = "test_namespace"
    @session1 = JWTSessions::Session.new(payload: payload, namespace: namespace)
    @session1.login
    refresh_token = @session1.instance_variable_get(:"@_refresh")
    access_token = @session1.instance_variable_get(:"@_access")
    uid = access_token.uid
    ruid = refresh_token.uid

    assert_equal access_token.csrf, JWTSessions::AccessToken.find(uid, JWTSessions.token_store).csrf
    flushed_count = @session1.flush_namespaced_access_tokens

    assert_equal 1, flushed_count
    assert_raises JWTSessions::Errors::Unauthorized do
      JWTSessions::AccessToken.find(uid, JWTSessions.token_store)
    end
    assert_equal ruid, JWTSessions::RefreshToken.find(ruid, JWTSessions.token_store, namespace).uid
  end

  def test_refresh_after_flush_namespaced_access_tokens
    namespace = "test_namespace"
    session = JWTSessions::Session.new(payload: payload, namespace: namespace, refresh_by_access_allowed: true)
    session.login

    session.flush_namespaced_access_tokens
    ruid = session.instance_variable_get(:"@_refresh").uid
    refresh_token = JWTSessions::RefreshToken.find(ruid, JWTSessions.token_store, namespace)
    assert_equal "0", refresh_token.access_uid
    assert_equal "0", refresh_token.access_expiration

    # allows to refresh with un-expired but flushed access token payload
    session.refresh_by_access_payload do
      raise JWTSessions::Errors::Unauthorized
    end
    auid = session.instance_variable_get(:"@_access").uid
    access_token = JWTSessions::AccessToken.find(auid, JWTSessions.token_store)
    refresh_token = JWTSessions::RefreshToken.find(ruid, JWTSessions.token_store, namespace)

    assert "0" != access_token.uid
    assert "0" != access_token.expiration
    assert_equal access_token.uid.to_s, refresh_token.access_uid
    assert_equal access_token.expiration.to_s, refresh_token.access_expiration
  end

  def test_flush_all
    refresh_token = @session.instance_variable_get(:"@_refresh")
    flushed_count = JWTSessions::Session.flush_all
    assert_equal 1, flushed_count
    assert_raises JWTSessions::Errors::Unauthorized do
      JWTSessions::RefreshToken.find(refresh_token.uid, JWTSessions.token_store, nil).token
    end
  end
end
