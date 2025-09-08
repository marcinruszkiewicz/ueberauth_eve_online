defmodule UeberauthEveOnline.MixProject do
  use Mix.Project

  @version "1.0.2"

  def project do
    [
      app: :ueberauth_eve_online,
      version: @version,
      name: "Ueberauth EVE Online",
      package: package(),
      elixir: "~> 1.18",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      source_url: "https://github.com/marcinruszkiewicz/ueberauth_eve_online",
      homepage_url: "https://github.com/marcinruszkiewicz/ueberauth_eve_online",
      description: description(),
      deps: deps(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:oauth2, "~> 2.0"},
      {:ueberauth, "~> 0.10"},

      # dev/test only dependencies
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:styler, "~> 1.1", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.22", only: [:dev, :test], runtime: false},
      {:mox, "~> 1.0", only: :test},
      {:plug_cowboy, "~> 2.0", only: :test},

      # docs dependencies
      {:ex_doc, "~> 0.38", only: :dev, runtime: false}
    ]
  end

  defp docs do
    [extras: ["README.md"]]
  end

  defp description do
    "An Ueberauth strategy for using EVE Online SSO to authenticate your users."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Marcin Ruszkiewicz"],
      licenses: ["MIT"],
      links: %{GitHub: "https://github.com/marcinruszkiewicz/ueberauth_eve_online"}
    ]
  end
end
