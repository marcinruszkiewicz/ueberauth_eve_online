# Überauth EVE Online

EVE Online SSO OAuth2 strategy for Überauth

> **Note**: This library is a maintained fork of the original [ueberauth_eve_sso](https://github.com/lukasni/ueberauth_eve_sso) by Lukas Niederberger. It has been updated to work with modern Elixir/OTP versions.

## Installation

1. Setup your application at the [EVE third party developer page](https://developers.eveonline.com/).

2. Add `:ueberauth_eve_online` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_eve_online, "~> 1.0"}]
    end
    ```

3. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_eve_online]]
    end
    ```

4. Add EVESSO to your ueberauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        evesso: {Ueberauth.Strategy.EVESSO, []}
      ]
    ```

5. Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
      client_id: System.get_env("EVESSO_CLIENT_ID"),
      client_secret: System.get_env("EVESSO_SECRET_KEY")
    ```

    Or, to read the client credentials at runtime:
    ```elixir
    config :ueberauth, Ueberauth.Strategy.EVESSO.OAuth,
      client_id: {:system, "EVESSO_CLIENT_ID"},
      client_secret: {:system, "EVESSO_SECRET_KEY"}
    ```

6. Include the Ueberauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller

      pipeline :browser do
        plug Ueberauth
        ...
      end
    end
    ```

7.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
    end
    ```

8. Your controller needs to implement callbacks to deal with `Ueberauth.Auth` and `Ueberauth.Failure` responses.

## HTTPS Configuration

If your application runs behind a proxy (nginx, load balancer) that terminates SSL, you may encounter redirect URI mismatches where EVE SSO receives `http://` URLs instead of `https://` URLs. Here are three ways to fix this:

### Option 1: Configure callback scheme
```elixir
config :ueberauth, Ueberauth,
  providers: [
    evesso: {Ueberauth.Strategy.EVESSO, [callback_scheme: "https"]}
  ]
```

### Option 2: Set explicit callback URL
```elixir
config :ueberauth, Ueberauth,
  providers: [
    evesso: {Ueberauth.Strategy.EVESSO, [callback_url: "https://your-domain.com/auth/evesso/callback"]}
  ]
```

### Option 3: Configure X-Forwarded-Proto header
Configure your proxy to set the `X-Forwarded-Proto: https` header, which Ueberauth will automatically detect.

**Note**: Make sure your EVE SSO application is configured with the same HTTPS callback URL in the [EVE Developers portal](https://developers.eveonline.com/).

## Calling

Depending on the configured url you can initiate the request through:

    /auth/evesso

Or with options:

    /auth/evesso?scope=esi-clones.read_implants.v1&state=nonce

By default the requested scope is empty (""). This allows access to all public endpoints and identifies the EVE Character.
Scope can be configured either explicitly as a `scope` query value on the request path or in your configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        evesso: {Ueberauth.Strategy.EVESSO, [default_scope: "esi-clones.read_implants.v1"]}
      ]
    ```

The `state` param is required by EVE SSO and should be a nonce generated for each request.

## License

Please see [LICENSE](https://github.com/marcinruszkiewicz/ueberauth_eve_online/blob/master/LICENSE) for licensing details.

## Credits

This library is based on the original [ueberauth_eve_sso](https://github.com/lukasni/ueberauth_eve_sso) created by Lukas Niederberger. We thank him for his excellent work that made this library possible.
