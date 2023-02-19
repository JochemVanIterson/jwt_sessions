# frozen_string_literal: true

module JWTSessions
  class RefreshToken
    attr_reader :expiration, :uid, :token, :csrf, :access_uid, :access_expiration, :store, :namespace

    def initialize(csrf,
                   access_uid,
                   access_expiration,
                   store,
                   options = {})
      @csrf              = csrf
      @access_uid        = access_uid
      @access_expiration = access_expiration
      @store             = store
      @uid               = options.fetch(:uid, nil) || SecureRandom.uuid
      @expiration        = options.fetch(:expiration, nil) || JWTSessions.refresh_expiration
      @namespace         = options.fetch(:namespace, nil)
      @token             = Token.encode(options.fetch(:payload, {}).merge("uid" => uid, "exp" => expiration.to_i))
    end

    class << self
      def create(csrf, access_uid, access_expiration, store, payload, namespace, expiration = JWTSessions.refresh_expiration)
        inst = new(
          csrf,
          access_uid,
          access_expiration,
          store,
          payload: payload,
          namespace: namespace,
          expiration: expiration
        )
        inst.send(:persist_in_store)
        inst
      end

      def all(namespace, store)
        tokens = store.all_refresh_tokens(namespace)
        tokens.map do |uid, token_attrs|
          build_with_token_attrs(store, uid, token_attrs, namespace)
        end
      end

      # first_match should be set to true when
      # we need to search through the all namespaces
      def find(uid, store, namespace = nil, first_match: false)
        token_attrs = store.fetch_refresh(uid, namespace, first_match)
        raise Errors::Unauthorized, "Refresh token not found" if token_attrs.empty?
        build_with_token_attrs(store, uid, token_attrs, namespace)
      end

      def destroy(uid, store, namespace)
        store.destroy_refresh(uid, namespace)
      end

      private

      def build_with_token_attrs(store, uid, token_attrs, namespace)
        new(
          token_attrs[:csrf],
          token_attrs[:access_uid],
          token_attrs[:access_expiration],
          store,
          namespace: token_attrs[:namespace] || namespace,
          payload: {},
          uid: uid,
          expiration: token_attrs[:expiration]
        )
      end
    end

    def update(access_uid, access_expiration, csrf, expiration = @expiration)
      @csrf              = csrf
      @access_uid        = access_uid
      @access_expiration = access_expiration
      @expiration        = expiration

      # Create new token with updated payload
      updated_refresh = {
        uid: uid,
        access_expiration: access_expiration,
        access_uid: access_uid,
        csrf: csrf,
        namespace: namespace
      }
      
      # Insert :expiration only if store.update_refresh method accepts it.
      # This is to support backward compatibility with older versions of custom stores.

      # Check if parameters includes :expiration
      update_refresh_parameters = store.method(:update_refresh).parameters
      if update_refresh_parameters.select{|_, x| x == :expiration}.length > 0
        updated_refresh[:expiration] = expiration
      end

      # Update refresh token in store using a key spread operator
      store.update_refresh(**updated_refresh)
    end

    def destroy
      store.destroy_refresh(uid, namespace)
    end

    private

    def persist_in_store
      store.persist_refresh(
        uid: uid,
        access_expiration: access_expiration,
        access_uid: access_uid,
        csrf: csrf,
        expiration: expiration,
        namespace: namespace
      )
    end
  end
end
