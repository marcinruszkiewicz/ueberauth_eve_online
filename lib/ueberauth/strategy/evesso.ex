defmodule Ueberauth.Strategy.EVESSO do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with EVE SSO v2.

  ### Setup

  Create an SSO Application on the [EVE Developers page](https://developers.eveonline.com/).

  After registering an application get the client id and secret key from the application details page.

  Include the credentials in the configuration for EVESSO

      config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: System.get_env("EVESSO_CLIENT_ID"),
        client_secret: System.get_env("EVESSO_SECRET_KEY")

  If you haven't already, create a pipeline and set up routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider/callback", AuthController, :callback
      end

  Create an endpoint for the callback where you will handle the Ueberauth.Auth struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback_phase(%{assigns: %{ueberauth_failure: fails}} = conn, _params) do
          #do things with the failure
        end

        def callback_phase(%{assigns: %{ueberauth_auth: auth}} = conn, params) do
          # do things with the auth
        end
      end

  You can edit the behaviour of the Strategy by including some options when you register your provider

  To set the `uid_field`

      config :ueberauth, Ueberauth,
        providers: [
          evesso: {Ueberauth.Strategy.EVESSO, [uid_field: :character_id]}
        ]

  Default is `:owner_hash`, others available are `:character_id` and `:name`

  To set the default scopes:

      config :ueberauth, Ueberauth,
        providers: [
          evesso: {Ueberauth.Strategy.EVESSO, [default_scope: "esi-clones.read_implants.v1 esi-characters.read_notifications.v1"]}
        ]

  Default is empty ("") which doesn't grant any extra permissions beyond public endpoints but enables you to verify character ownership.
  Scopes are provided as a space-separated list.

  ### HTTPS Configuration

  If your application runs behind a proxy (nginx, load balancer) that terminates SSL, you may need to configure
  the callback URL scheme to use HTTPS:

      config :ueberauth, Ueberauth,
        providers: [
          evesso: {Ueberauth.Strategy.EVESSO, [callback_scheme: "https"]}
        ]

  You can also set a specific callback URL:

      config :ueberauth, Ueberauth,
        providers: [
          evesso: {Ueberauth.Strategy.EVESSO, [callback_url: "https://your-domain.com/auth/evesso/callback"]}
        ]

  Or configure your web server to set the `X-Forwarded-Proto` header to `https` for proper scheme detection.
  """
  use Ueberauth.Strategy,
    uid_field: :owner_hash,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.EVESSO.OAuth

  alias Ueberauth.Auth.{Info, Credentials, Extra}

  @doc """
  Handles the initial redirect to the EVE SSO authentication page

  To customize the scopes that are requested from SSO include them as part of your url:

      "/auth/evesso?scope=esi-clones.read_implants.v1"

  EVE SSO v2 also requires a `state` param that will be returned and can be used to guard against MITM attacks.
  """
  @spec handle_request!(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    # Apply callback configuration for HTTPS support
    conn = apply_callback_config(conn)

    opts =
      if send_redirect_uri do
        [redirect_uri: callback_url(conn), scope: scopes]
      else
        [scope: scopes]
      end

    opts = Keyword.put(opts, :state, conn.private[:ueberauth_state_param])

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from EVE SSO. When there is a failure from EVE SSO the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned in the token is returned in the Ueberauth.Auth struct.
  """
  @spec handle_callback!(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_callback!(%Plug.Conn{params: %{"code" => code, "state" => state}} = conn) do
    # Get expected state from cookie (fix for ueberauth state cookie bug)
    expected_state = conn.private[:ueberauth_state_param] || Map.get(conn.req_cookies, "ueberauth.state_param")

    if state != expected_state do
      set_errors!(conn, [error("invalid_state", "Invalid state parameter. Possible CSRF attack.")])
    else
      exchange_code_for_token(conn, code)
    end
  end

  @spec handle_callback!(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    # If no state is provided, log a warning but continue (for backward compatibility)
    require Logger

    Logger.warning(
      "No state parameter provided in EVE SSO callback - consider enabling state validation for security"
    )

    exchange_code_for_token(conn, code)
  end

  @spec handle_callback!(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw SSO response around during the callback phase
  """
  @spec handle_cleanup!(Plug.Conn.t()) :: Plug.Conn.t()
  def handle_cleanup!(conn) do
    conn
    |> put_private(:evesso_token, nil)
    |> put_private(:evesso_user, nil)
  end

  @doc """
  Fetches the uid field from the token payload. This defaults to the option `uid_field` which in turn defaults to `owner_hash`
  """
  @spec uid(Plug.Conn.t()) :: any()
  def uid(conn) do
    conn |> option(:uid_field) |> fetch_uid(conn)
  end

  @doc """
  Includes the credentials from the SSO response.
  """
  @spec credentials(Plug.Conn.t()) :: Credentials.t()
  def credentials(conn) do
    token = conn.private.evesso_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, " ")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  @spec info(Plug.Conn.t()) :: Info.t()
  def info(conn) do
    user = conn.private.evesso_user

    %Info{
      name: user.name
    }
  end

  @doc """
  Stores the raw information, including the token, obtained from the SSO callback.
  """
  @spec extra(Plug.Conn.t()) :: Extra.t()
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.evesso_token,
        user: conn.private.evesso_user
      }
    }
  end

  defp fetch_uid(field, conn) do
    conn.private.evesso_user[field]
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :evesso_token, token)

    with {:ok, verified} <- Ueberauth.Strategy.EVESSO.OAuth.verify(token),
         {:ok, user} <- extra_user_info(verified) do
      put_private(conn, :evesso_user, user)
    else
      {:error, reason} ->
        set_errors!(conn, error("Verify", reason))

      _err ->
        set_errors!(conn, error("Verify", "Unexpected error during verification"))
    end
  end

  defp extra_user_info(verify) do
    character_id =
      verify["sub"]
      |> String.replace("CHARACTER:EVE:", "")
      |> String.to_integer()

    user = %{
      name: verify["name"],
      character_id: character_id,
      owner_hash: verify["owner"]
    }

    {:ok, user}
  end

  # Exchange authorization code for access token
  defp exchange_code_for_token(conn, code) do
    module = option(conn, :oauth2_module)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)

    # Apply callback configuration for HTTPS support
    conn = apply_callback_config(conn)

    params = if send_redirect_uri do
      [code: code, redirect_uri: callback_url(conn)]
    else
      [code: code]
    end

    try do
      token = apply(module, :get_token!, [params])

      if token.access_token == nil do
        set_errors!(conn, [
          error(token.other_params["error"], token.other_params["error_description"])
        ])
      else
        fetch_user(conn, token)
      end
    rescue
      e in OAuth2.Error ->
        # Handle OAuth2 errors gracefully
        {error_code, error_description} = parse_oauth_error(e)
        set_errors!(conn, [error(error_code, error_description)])
    end
  end

  # Parse OAuth2.Error into user-friendly error messages
  defp parse_oauth_error(%OAuth2.Error{reason: %{body: body}}) when is_binary(body) do
    case Ueberauth.json_library().decode(body) do
      {:ok, %{"error" => "invalid_grant", "error_description" => desc}} ->
        {"invalid_grant", desc}

      {:ok, %{"error" => "invalid_grant"}} ->
        {"invalid_grant",
         "Authorization code is invalid or expired. Please try logging in again."}

      {:ok, %{"error" => error, "error_description" => desc}} ->
        {error, desc}

      {:ok, %{"error" => error}} ->
        {error, "OAuth2 authentication failed"}

      _ ->
        {"oauth2_error", "Authentication failed"}
    end
  end

  # Handle network-related errors
  defp parse_oauth_error(%OAuth2.Error{reason: %{reason: :nxdomain}}) do
    {"network_error", "Unable to connect to EVE SSO. Please check your internet connection."}
  end

  defp parse_oauth_error(%OAuth2.Error{reason: %{reason: :timeout}}) do
    {"network_error", "EVE SSO request timed out. Please try again later."}
  end

  defp parse_oauth_error(%OAuth2.Error{reason: %{reason: :econnrefused}}) do
    {"network_error", "Unable to connect to EVE SSO. Service may be temporarily unavailable."}
  end

  defp parse_oauth_error(%OAuth2.Error{reason: reason}) when is_binary(reason) do
    {"oauth2_error", reason}
  end

  defp parse_oauth_error(_) do
    {"oauth2_error", "OAuth2 authentication failed"}
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  # Apply callback configuration options to support HTTPS
  defp apply_callback_config(conn) do
    options = options(conn)
    
    # Get existing request options - can be either a map (real Ueberauth) or keyword list (tests)
    existing_opts = conn.private[:ueberauth_request_options]
    
    # Handle different data structures from Ueberauth vs tests
    existing_opts = case existing_opts do
      nil -> %{}  # Default to map for real usage
      opts when is_list(opts) -> opts  # Keep as keyword list for tests
      opts when is_map(opts) -> opts   # Keep as map for real usage
    end
    
    # Add callback configuration to request options
    updated_opts = existing_opts
    |> maybe_put_callback_url_opt(Keyword.get(options, :callback_url))
    |> maybe_put_callback_scheme_opt(Keyword.get(options, :callback_scheme))
    
    put_private(conn, :ueberauth_request_options, updated_opts)
  end

  defp maybe_put_callback_url_opt(opts, nil), do: opts
  defp maybe_put_callback_url_opt(opts, callback_url) when is_map(opts) do
    Map.put(opts, :callback_url, callback_url)
  end
  defp maybe_put_callback_url_opt(opts, callback_url) when is_list(opts) do
    Keyword.put(opts, :callback_url, callback_url)
  end

  defp maybe_put_callback_scheme_opt(opts, nil), do: opts
  defp maybe_put_callback_scheme_opt(opts, callback_scheme) when is_map(opts) do
    Map.put(opts, :callback_scheme, callback_scheme)
  end
  defp maybe_put_callback_scheme_opt(opts, callback_scheme) when is_list(opts) do
    Keyword.put(opts, :callback_scheme, callback_scheme)
  end
end
