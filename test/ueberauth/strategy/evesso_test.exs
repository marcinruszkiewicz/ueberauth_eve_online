defmodule Ueberauth.Strategy.EVESSOTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn

  alias Ueberauth.Strategy.EVESSO
  alias Ueberauth.Auth.{Info, Credentials, Extra}

  # Mock modules for testing
  defmodule MockOAuth do
    def authorize_url!(opts) do
      params = Keyword.get(opts, :scope, "")
      state = Keyword.get(opts, :state, "")
      "https://login.eveonline.com/v2/oauth/authorize?scope=#{params}&state=#{state}"
    end

    def get_token!(opts) do
      case Keyword.get(opts, :code) do
        "valid_code" ->
          %OAuth2.AccessToken{
            access_token:
              "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXVC1TaWduaXR1cmUtS2V5IiwidHlwIjoiSldUIn0.eyJzY3AiOlsiZXNpLWNsb25lcy5yZWFkX2ltcGxhbnRzLnYxIl0sImp0aSI6IjEyMzQ1Njc4LTlhYmMtZGVmMC0xMjM0LTU2Nzg5YWJjZGVmMCIsImtpZCI6IkpXVC1TaWduaXR1cmUtS2V5IiwiaXNzIjoibG9naW4uZXZlb25saW5lLmNvbSIsImF1ZCI6WyJFVkUtU1NPLXYyIl0sInN1YiI6IkNIQVJBQ1RFUjpFVkU6MTIzNDU2Nzg5MCIsImV4cCI6MTcwMDAwMDAwMCwiaWF0IjoxNjAwMDAwMDAwLCJuYW1lIjoiVGVzdCBDaGFyYWN0ZXIiLCJvd25lciI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6In0.signature",
            refresh_token: "refresh_token",
            expires_at: 1_700_000_000,
            token_type: "Bearer",
            other_params: %{"scope" => "esi-clones.read_implants.v1"}
          }

        "invalid_code" ->
          %OAuth2.AccessToken{
            access_token: nil,
            other_params: %{
              "error" => "invalid_grant",
              "error_description" => "Invalid authorization code"
            }
          }

        _ ->
          %OAuth2.AccessToken{access_token: "invalid_token"}
      end
    end

    def verify(token) do
      case token.access_token do
        "eyJhbGciOiJSUzI1NiIsImtpZCI6IkpXVC1TaWduaXR1cmUtS2V5IiwidHlwIjoiSldUIn0.eyJzY3AiOlsiZXNpLWNsb25lcy5yZWFkX2ltcGxhbnRzLnYxIl0sImp0aSI6IjEyMzQ1Njc4LTlhYmMtZGVmMC0xMjM0LTU2Nzg5YWJjZGVmMCIsImtpZCI6IkpXVC1TaWduaXR1cmUtS2V5IiwiaXNzIjoibG9naW4uZXZlb25saW5lLmNvbSIsImF1ZCI6WyJFVkUtU1NPLXYyIl0sInN1YiI6IkNIQVJBQ1RFUjpFVkU6MTIzNDU2Nzg5MCIsImV4cCI6MTcwMDAwMDAwMCwiaWF0IjoxNjAwMDAwMDAwLCJuYW1lIjoiVGVzdCBDaGFyYWN0ZXIiLCJvd25lciI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6In0.signature" ->
          {:ok,
           %{
             "scp" => ["esi-clones.read_implants.v1"],
             "jti" => "12345678-9abc-def0-1234-56789abcdef0",
             "kid" => "JWT-Signature-Key",
             "iss" => "login.eveonline.com",
             "aud" => ["EVE-SSO-v2"],
             "sub" => "CHARACTER:EVE:1234567890",
             "exp" => 1_700_000_000,
             "iat" => 1_600_000_000,
             "name" => "Test Character",
             "owner" => "abcdefghijklmnopqrstuvwxyz"
           }}

        _ ->
          {:error, "Invalid token"}
      end
    end
  end

  setup do
    # Create a basic connection
    conn =
      conn(:get, "/auth/evesso")
      |> Map.put(:params, %{})
      |> init_test_session(%{})
      |> put_private(:ueberauth_state_param, "test_state")

    %{conn: conn}
  end

  describe "handle_request!/1" do
    test "redirects to EVE SSO authorization URL with default scope", %{conn: conn} do
      conn =
        conn
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_request!(conn)

      assert result.status == 302

      assert get_resp_header(result, "location") |> hd() =~
               "https://login.eveonline.com/v2/oauth/authorize"

      assert get_resp_header(result, "location") |> hd() =~ "state=test_state"
    end

    test "redirects with custom scope from params", %{conn: conn} do
      conn =
        conn
        |> Map.put(:params, %{"scope" => "esi-clones.read_implants.v1"})
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_request!(conn)

      assert result.status == 302
      assert get_resp_header(result, "location") |> hd() =~ "scope=esi-clones.read_implants.v1"
    end

    test "redirects with configured default scope", %{conn: conn} do
      conn =
        conn
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [
            oauth2_module: MockOAuth,
            default_scope: "esi-characters.read_notifications.v1"
          ]
        )

      result = EVESSO.handle_request!(conn)

      assert result.status == 302

      assert get_resp_header(result, "location") |> hd() =~
               "scope=esi-characters.read_notifications.v1"
    end
  end

  describe "handle_callback!/1" do
    test "handles successful callback with valid code", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code")
        |> Map.put(:params, %{"code" => "valid_code"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.private[:evesso_token]
      assert result.private[:evesso_user]
      assert result.private[:evesso_user][:name] == "Test Character"
      assert result.private[:evesso_user][:character_id] == 1_234_567_890
      assert result.private[:evesso_user][:owner_hash] == "abcdefghijklmnopqrstuvwxyz"
    end

    test "handles callback with invalid code", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=invalid_code")
        |> Map.put(:params, %{"code" => "invalid_code"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]
      assert failure.errors |> List.first() |> Map.get(:message) == "Invalid authorization code"
    end

    test "handles callback without code parameter", %{} do
      conn =
        conn(:get, "/auth/evesso/callback")
        |> Map.put(:params, %{})
        |> init_test_session(%{})

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]
      assert failure.errors |> List.first() |> Map.get(:message) == "No code received"
    end

    test "validates state parameter when present", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code&state=wrong_state")
        |> Map.put(:params, %{"code" => "valid_code", "state" => "wrong_state"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_state_param, "correct_state")
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]

      assert failure.errors |> List.first() |> Map.get(:message) ==
               "Invalid state parameter. Possible CSRF attack."
    end

    test "validates state parameter with correct state", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code&state=correct_state")
        |> Map.put(:params, %{"code" => "valid_code", "state" => "correct_state"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_state_param, "correct_state")
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.private[:evesso_token]
      assert result.private[:evesso_user]
      refute result.assigns[:ueberauth_failure]
    end

    test "falls back to cookie when ueberauth_state_param is nil", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code&state=cookie_state")
        |> Map.put(:params, %{"code" => "valid_code", "state" => "cookie_state"})
        |> Map.put(:req_cookies, %{"ueberauth.state_param" => "cookie_state"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_state_param, nil)
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.private[:evesso_token]
      assert result.private[:evesso_user]
      refute result.assigns[:ueberauth_failure]
    end

    test "fails when state param doesn't match cookie fallback", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code&state=wrong_state")
        |> Map.put(:params, %{"code" => "valid_code", "state" => "wrong_state"})
        |> Map.put(:req_cookies, %{"ueberauth.state_param" => "cookie_state"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_state_param, nil)
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]

      assert failure.errors |> List.first() |> Map.get(:message) ==
               "Invalid state parameter. Possible CSRF attack."
    end

    test "prefers private state param over cookie when both present", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code&state=private_state")
        |> Map.put(:params, %{"code" => "valid_code", "state" => "private_state"})
        |> Map.put(:req_cookies, %{"ueberauth.state_param" => "cookie_state"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_state_param, "private_state")
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.private[:evesso_token]
      assert result.private[:evesso_user]
      refute result.assigns[:ueberauth_failure]
    end

    test "fails when no state source is available", %{} do
      conn =
        conn(:get, "/auth/evesso/callback?code=valid_code&state=some_state")
        |> Map.put(:params, %{"code" => "valid_code", "state" => "some_state"})
        |> Map.put(:req_cookies, %{})
        |> init_test_session(%{})
        |> put_private(:ueberauth_state_param, nil)
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuth,
          options: [oauth2_module: MockOAuth]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]

      assert failure.errors |> List.first() |> Map.get(:message) ==
               "Invalid state parameter. Possible CSRF attack."
    end

    test "handles OAuth2 errors gracefully", %{} do
      # Mock OAuth module that raises OAuth2.Error
      defmodule MockOAuthWithError do
        def get_token!(_) do
          raise OAuth2.Error,
            reason: %{
              body:
                ~s({"error": "invalid_grant", "error_description": "The authorization code is invalid"})
            }
        end
      end

      conn =
        conn(:get, "/auth/evesso/callback?code=error_code")
        |> Map.put(:params, %{"code" => "error_code"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuthWithError,
          options: [oauth2_module: MockOAuthWithError]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]

      assert failure.errors |> List.first() |> Map.get(:message) ==
               "The authorization code is invalid"
    end

    test "handles network errors gracefully", %{} do
      # Mock OAuth module that raises network error
      defmodule MockOAuthWithNetworkError do
        def get_token!(_) do
          raise OAuth2.Error, reason: %{reason: :timeout}
        end
      end

      conn =
        conn(:get, "/auth/evesso/callback?code=network_error")
        |> Map.put(:params, %{"code" => "network_error"})
        |> init_test_session(%{})
        |> put_private(:ueberauth_request_options,
          oauth2_module: MockOAuthWithNetworkError,
          options: [oauth2_module: MockOAuthWithNetworkError]
        )

      result = EVESSO.handle_callback!(conn)

      assert result.assigns[:ueberauth_failure]
      failure = result.assigns[:ueberauth_failure]

      assert failure.errors |> List.first() |> Map.get(:message) ==
               "EVE SSO request timed out. Please try again later."
    end
  end

  describe "handle_cleanup!/1" do
    test "clears private EVE SSO data", %{conn: conn} do
      conn =
        conn
        |> put_private(:evesso_token, %{token: "test"})
        |> put_private(:evesso_user, %{name: "test"})

      result = EVESSO.handle_cleanup!(conn)

      assert result.private[:evesso_token] == nil
      assert result.private[:evesso_user] == nil
    end
  end

  describe "uid/1" do
    test "returns owner_hash by default", %{conn: conn} do
      conn =
        conn
        |> put_private(:evesso_user, %{
          owner_hash: "test_owner_hash",
          character_id: 123,
          name: "Test Character"
        })
        |> put_private(:ueberauth_request_options, options: [])

      result = EVESSO.uid(conn)

      assert result == "test_owner_hash"
    end

    test "returns character_id when configured", %{conn: conn} do
      conn =
        conn
        |> put_private(:evesso_user, %{
          owner_hash: "test_owner_hash",
          character_id: 123,
          name: "Test Character"
        })
        |> put_private(:ueberauth_request_options,
          uid_field: :character_id,
          options: [uid_field: :character_id]
        )

      result = EVESSO.uid(conn)

      assert result == 123
    end

    test "returns name when configured", %{conn: conn} do
      conn =
        conn
        |> put_private(:evesso_user, %{
          owner_hash: "test_owner_hash",
          character_id: 123,
          name: "Test Character"
        })
        |> put_private(:ueberauth_request_options, uid_field: :name, options: [uid_field: :name])

      result = EVESSO.uid(conn)

      assert result == "Test Character"
    end
  end

  describe "credentials/1" do
    test "returns proper credentials struct", %{conn: conn} do
      token = %OAuth2.AccessToken{
        access_token: "access_token",
        refresh_token: "refresh_token",
        expires_at: 1_700_000_000,
        token_type: "Bearer",
        other_params: %{
          "scope" => "esi-clones.read_implants.v1 esi-characters.read_notifications.v1"
        }
      }

      conn = put_private(conn, :evesso_token, token)

      result = EVESSO.credentials(conn)

      assert %Credentials{} = result
      assert result.token == "access_token"
      assert result.refresh_token == "refresh_token"
      assert result.expires_at == 1_700_000_000
      assert result.token_type == "Bearer"
      assert result.expires == true

      assert result.scopes == [
               "esi-clones.read_implants.v1",
               "esi-characters.read_notifications.v1"
             ]
    end

    test "handles empty scope", %{conn: conn} do
      token = %OAuth2.AccessToken{
        access_token: "access_token",
        refresh_token: "refresh_token",
        expires_at: 1_700_000_000,
        token_type: "Bearer",
        other_params: %{}
      }

      conn = put_private(conn, :evesso_token, token)

      result = EVESSO.credentials(conn)

      assert result.scopes == [""]
    end
  end

  describe "info/1" do
    test "returns proper info struct", %{conn: conn} do
      user = %{
        name: "Test Character",
        character_id: 1_234_567_890,
        owner_hash: "test_owner_hash"
      }

      conn = put_private(conn, :evesso_user, user)

      result = EVESSO.info(conn)

      assert %Info{} = result
      assert result.name == "Test Character"
    end
  end

  describe "extra/1" do
    test "returns proper extra struct with raw info", %{conn: conn} do
      token = %OAuth2.AccessToken{access_token: "test_token"}
      user = %{name: "Test Character"}

      conn =
        conn
        |> put_private(:evesso_token, token)
        |> put_private(:evesso_user, user)

      result = EVESSO.extra(conn)

      assert %Extra{} = result
      assert result.raw_info.token == token
      assert result.raw_info.user == user
    end
  end
end
