defmodule Ueberauth.Strategy.EVESSO.OAuthTest do
  use ExUnit.Case, async: true

  alias Ueberauth.Strategy.EVESSO.OAuth

  describe "client/1" do
    setup do
      # Set up test configuration
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: "test_client_id",
        client_secret: "test_client_secret"
      )

      on_exit(fn ->
        Application.delete_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth)
      end)
    end

    test "creates OAuth2 client with default configuration" do
      client = OAuth.client()

      assert client.client_id == "test_client_id"
      assert client.client_secret == "test_client_secret"
      assert client.site == "https://esi.evetech.net"
      assert client.authorize_url == "https://login.eveonline.com/v2/oauth/authorize"
      assert client.token_url == "https://login.eveonline.com/v2/oauth/token"
    end

    test "creates OAuth2 client with custom options" do
      client = OAuth.client(redirect_uri: "http://localhost:4000/auth/evesso/callback")

      assert client.redirect_uri == "http://localhost:4000/auth/evesso/callback"
    end

    test "handles {:system, env_var} configuration" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: {:system, "TEST_CLIENT_ID"},
        client_secret: {:system, "TEST_CLIENT_SECRET"}
      )

      System.put_env("TEST_CLIENT_ID", "env_client_id")
      System.put_env("TEST_CLIENT_SECRET", "env_client_secret")

      client = OAuth.client()

      assert client.client_id == "env_client_id"
      assert client.client_secret == "env_client_secret"

      # Clean up
      System.delete_env("TEST_CLIENT_ID")
      System.delete_env("TEST_CLIENT_SECRET")
    end

    test "raises error when environment variable is missing" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: {:system, "MISSING_CLIENT_ID"},
        client_secret: "test_secret"
      )

      assert_raise RuntimeError, ~r/"MISSING_CLIENT_ID" missing from environment/, fn ->
        OAuth.client()
      end
    end

    test "raises error when client_id is missing from config" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_secret: "test_secret"
      )

      assert_raise RuntimeError, ~r/:client_id missing from config/, fn ->
        OAuth.client()
      end
    end

    test "raises error when client_secret is missing from config" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth, client_id: "test_id")

      assert_raise RuntimeError, ~r/:client_secret missing from config/, fn ->
        OAuth.client()
      end
    end

    test "raises error when config is not a keyword list" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth, "invalid_config")

      assert_raise RuntimeError,
                   ~r/Config :ueberauth, Ueberauth.Strategy.EVESSO is not a keyword list/,
                   fn ->
                     OAuth.client()
                   end
    end
  end

  describe "authorize_url!/2" do
    setup do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: "test_client_id",
        client_secret: "test_client_secret"
      )

      on_exit(fn ->
        Application.delete_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth)
      end)
    end

    test "generates authorize URL with parameters" do
      url = OAuth.authorize_url!(scope: "esi-clones.read_implants.v1", state: "test_state")

      assert url =~ "https://login.eveonline.com/v2/oauth/authorize"
      assert url =~ "client_id=test_client_id"
      assert url =~ "scope=esi-clones.read_implants.v1"
      assert url =~ "state=test_state"
    end

    test "generates authorize URL with custom client options" do
      url =
        OAuth.authorize_url!(
          [scope: "esi-clones.read_implants.v1"],
          redirect_uri: "http://localhost:4000/auth/evesso/callback"
        )

      assert url =~ "https://login.eveonline.com/v2/oauth/authorize"
      assert url =~ "redirect_uri="
    end
  end

  describe "get/4" do
    setup do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: "test_client_id",
        client_secret: "test_client_secret"
      )

      on_exit(fn ->
        Application.delete_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth)
      end)
    end

    # Note: This test would normally require HTTP mocking
    # For now, we'll test the function signature and structure
    test "accepts correct parameters" do
      token = %OAuth2.AccessToken{access_token: "test_token"}

      # We just verify the function exists and accepts the right parameters
      # The function should return an OAuth2.Response or OAuth2.Error struct
      result = OAuth.get(token, "/test", [], [])

      # Should return some response structure (success or error)
      case result do
        %OAuth2.Response{} -> assert true
        {:error, %OAuth2.Response{}} -> assert true
        _ -> flunk("Unexpected result: #{inspect(result)}")
      end
    end
  end

  describe "verify/1" do
    test "successfully decodes valid JWT token" do
      # This is a mock JWT token with a properly base64-encoded payload
      # Payload: {"sub":"CHARACTER:EVE:1234567890","name":"Test Character","owner":"abcdefghijklmnopqrstuvwxyz"}
      mock_token = %OAuth2.AccessToken{
        access_token:
          "header.eyJzdWIiOiJDSEFSQUNURVI6RVZFOjEyMzQ1Njc4OTAiLCJuYW1lIjoiVGVzdCBDaGFyYWN0ZXIiLCJvd25lciI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6In0.signature"
      }

      {:ok, decoded} = OAuth.verify(mock_token)

      assert decoded["sub"] == "CHARACTER:EVE:1234567890"
      assert decoded["name"] == "Test Character"
      assert decoded["owner"] == "abcdefghijklmnopqrstuvwxyz"
    end

    test "handles malformed JWT token" do
      mock_token = %OAuth2.AccessToken{access_token: "invalid.token"}

      {:error, reason} = OAuth.verify(mock_token)

      assert reason == "invalid JWT format - expected 3 parts separated by dots"
    end

    test "handles invalid token format" do
      mock_token = %OAuth2.AccessToken{access_token: "invalid_token_format"}

      {:error, reason} = OAuth.verify(mock_token)

      assert reason == "invalid JWT format - expected 3 parts separated by dots"
    end

    test "handles JSON decode errors" do
      # Token with invalid JSON in the payload
      mock_token = %OAuth2.AccessToken{
        access_token: "header.aW52YWxpZF9qc29u.signature"
      }

      {:error, reason} = OAuth.verify(mock_token)
      assert reason =~ "failed to decode JSON"
    end

    test "handles nil token" do
      mock_token = %OAuth2.AccessToken{access_token: nil}

      {:error, reason} = OAuth.verify(mock_token)
      assert reason == "token is nil"
    end

    test "handles non-string token" do
      mock_token = %OAuth2.AccessToken{access_token: 123}

      {:error, reason} = OAuth.verify(mock_token)
      assert reason == "access_token must be a string"
    end

    test "handles invalid JWT format" do
      mock_token = %OAuth2.AccessToken{access_token: "invalid.format"}

      {:error, reason} = OAuth.verify(mock_token)
      assert reason == "invalid JWT format - expected 3 parts separated by dots"
    end

    test "handles missing required claims" do
      # Token with missing 'name' and 'owner' claims
      # Payload: {"sub":"CHARACTER:EVE:1234567890"}
      mock_token = %OAuth2.AccessToken{
        access_token: "header.eyJzdWIiOiJDSEFSQUNURVI6RVZFOjEyMzQ1Njc4OTAifQ.signature"
      }

      {:error, reason} = OAuth.verify(mock_token)
      assert reason == "missing required claims: name and/or owner"
    end

    test "handles missing sub claim" do
      # Token with missing 'sub' claim
      # Payload: {"name":"Test Character","owner":"abcdefghijklmnopqrstuvwxyz"}
      mock_token = %OAuth2.AccessToken{
        access_token:
          "header.eyJuYW1lIjoiVGVzdCBDaGFyYWN0ZXIiLCJvd25lciI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6In0.signature"
      }

      {:error, reason} = OAuth.verify(mock_token)
      assert reason == "missing required claim: sub (subject)"
    end
  end

  describe "authorize_url/2" do
    test "delegates to OAuth2.Strategy.AuthCode.authorize_url/2" do
      # Create a mock client
      client = %OAuth2.Client{
        client_id: "test_id",
        client_secret: "test_secret",
        authorize_url: "https://login.eveonline.com/v2/oauth/authorize"
      }

      params = [scope: "test_scope"]

      # This should return a client with the authorize_url set
      result = OAuth.authorize_url(client, params)

      assert %OAuth2.Client{} = result
    end
  end

  describe "get_token/3" do
    test "processes client correctly and removes client_id param" do
      client = %OAuth2.Client{
        client_id: "test_id",
        client_secret: "test_secret",
        token_url: "https://login.eveonline.com/v2/oauth/token",
        params: %{"client_id" => "test_id", "other_param" => "value"}
      }

      params = [code: "test_code"]
      headers = []

      # The function should process and return a client (this will modify the client)
      result = OAuth.get_token(client, params, headers)

      # Should return a client struct
      assert %OAuth2.Client{} = result
      # Should have removed the client_id parameter from params
      refute Map.has_key?(result.params, "client_id")
    end
  end

  describe "get_token!/2" do
    setup do
      Application.put_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: "test_client_id",
        client_secret: "test_client_secret"
      )

      on_exit(fn ->
        Application.delete_env(:ueberauth, Ueberauth.Strategy.EVESSO.OAuth)
      end)
    end

    # Note: This test would normally require HTTP mocking for the actual token request
    test "accepts correct parameters" do
      params = [code: "test_code"]
      options = [headers: [], options: [], client_options: []]

      # This will fail with a real HTTP request due to invalid credentials
      assert_raise OAuth2.Error, fn ->
        OAuth.get_token!(params, options)
      end
    end
  end
end
