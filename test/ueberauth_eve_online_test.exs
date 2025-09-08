defmodule UeberauthEveOnlineTest do
  use ExUnit.Case, async: true

  doctest UeberauthEveOnline

  test "module exists" do
    assert Code.ensure_loaded?(UeberauthEveOnline)
  end
end
