defmodule Ueberauth.Strategy.EVESSO.OAuth do
  @moduledoc """
  An implementation of OAuth2 for EVE SSO

  To add your `client_id` and `client_secret` include these values in your configuration.

      config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
        client_id: System.get_env("EVESSO_CLIENT_ID"),
        client_secret: System.get_env("EVESSO_SECRET_KEY")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://esi.evetech.net",
    authorize_url: "https://login.eveonline.com/v2/oauth/authorize",
    token_url: "https://login.eveonline.com/v2/oauth/token"
  ]

  @doc """
  Construct a client for requests to EVE SSO

  Optionally include any OAuth2 options here to be merged with the defaults.

      Ueberauth.Strategy.EVESSO.OAuth.client(redired_uri: "http://localhost:4000/auth/evesso/callback")

  This will be set up automatically for you in `Ueberauth.Strategy.EVESSO`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  @spec client(keyword()) :: OAuth2.Client.t()
  def client(opts \\ []) do
    config =
      :ueberauth
      |> Application.fetch_env!(__MODULE__)
      |> check_credential(:client_id)
      |> check_credential(:client_secret)

    client_opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    json_library = Ueberauth.json_library()

    client_opts
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this directly usually.
  """
  @spec authorize_url!(keyword(), keyword()) :: String.t()
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  @doc """
  Fetch a URL using the access token for authentication.

  Most users of this library should not need to call this directly.
  """
  @spec get(OAuth2.AccessToken.t(), String.t(), keyword(), keyword()) :: OAuth2.Response.t()
  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> OAuth2.Client.get(url, headers, opts)
  end

  @doc """
  Request an access token from EVE SSO.

  This is called automatically by the Ueberauth flow.
  """
  @spec get_token!(keyword(), keyword()) :: OAuth2.AccessToken.t()
  def get_token!(params \\ [], options \\ []) do
    # Add configurable timeout
    timeout = Application.get_env(:ueberauth, :request_timeout, 30_000)

    headers = Keyword.get(options, :headers, [])

    request_options =
      [timeout: timeout]
      |> Keyword.merge(Keyword.get(options, :options, []))

    client_options = Keyword.get(options, :client_options, [])

    client = OAuth2.Client.get_token!(client(client_options), params, headers, request_options)

    client.token
  end

  @doc """
  Decodes the JWT locally and retrieves the user information held within.

  More work could be done here to actually validate the token, see
  [ESI docs](https://docs.esi.evetech.net/docs/sso/validating_eve_jwt.html) for details

  """
  @spec verify(OAuth2.AccessToken.t()) :: {:ok, map()} | {:error, String.t()}
  def verify(token) do
    case token.access_token do
      nil ->
        {:error, "token is nil"}

      access_token when is_binary(access_token) ->
        case String.split(access_token, ".") do
          [_header, payload, _signature] ->
            decode_jwt_payload(payload)

          _ ->
            {:error, "invalid JWT format - expected 3 parts separated by dots"}
        end

      _ ->
        {:error, "access_token must be a string"}
    end
  end

  # Helper function to decode JWT payload
  defp decode_jwt_payload(payload) do
    with {:ok, json_string} <- Base.decode64(payload, padding: false),
         {:ok, decoded} <- Ueberauth.json_library().decode(json_string) do
      validate_jwt_claims(decoded)
    else
      {:error, %Jason.DecodeError{} = error} ->
        {:error, "failed to decode JSON: #{Exception.message(error)}"}

      {:error, json_error} ->
        {:error, "JSON decode error: #{inspect(json_error)}"}

      :error ->
        {:error, "failed to decode base64 - invalid padding or format"}
    end
  end

  # Validate essential JWT claims
  defp validate_jwt_claims(%{"sub" => sub, "name" => name, "owner" => owner} = claims)
       when is_binary(sub) and is_binary(name) and is_binary(owner) do
    {:ok, claims}
  end

  defp validate_jwt_claims(%{"sub" => sub}) when is_binary(sub) do
    {:error, "missing required claims: name and/or owner"}
  end

  defp validate_jwt_claims(_) do
    {:error, "missing required claim: sub (subject)"}
  end

  # Strategy Callbacks

  @doc """
  OAuth2 strategy callback to generate the authorization URL.

  This is called automatically by the OAuth2 client.
  """
  @spec authorize_url(OAuth2.Client.t(), keyword()) :: OAuth2.Client.t()
  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  @doc """
  OAuth2 strategy callback to get the access token from EVE SSO.

  This handles the EVE SSO requirement that client credentials should not be
  duplicated in both the Authorization header and request body.
  """
  @spec get_token(OAuth2.Client.t(), keyword(), keyword()) :: OAuth2.Client.t()
  def get_token(client, params, headers) do
    # EVE SSO does not like to receive duplicate credentials such as Basic auth header and client_id in the body
    # OAuth2 adds them to both, so we need to delete the client_id parameter manually
    client
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
    |> delete_param(:client_id)
  end

  defp delete_param(%{params: params} = client, key) do
    %{client | params: Map.delete(params, "#{key}")}
  end

  defp check_credential(config, key) do
    check_config_key_exists(config, key)

    case Keyword.get(config, key) do
      value when is_binary(value) ->
        config

      {:system, env_key} ->
        case System.get_env(env_key) do
          nil ->
            raise "#{inspect(env_key)} missing from environment, expected in config :ueberauth, Ueberauth.Strategy.EVESSO"

          value ->
            Keyword.put(config, key, value)
        end
    end
  end

  defp check_config_key_exists(config, key) when is_list(config) do
    unless Keyword.has_key?(config, key) do
      raise "#{inspect(key)} missing from config :ueberauth, Ueberauth.Strategy.EVESSO"
    end

    config
  end

  defp check_config_key_exists(_, _) do
    raise "Config :ueberauth, Ueberauth.Strategy.EVESSO is not a keyword list, as expected"
  end
end
