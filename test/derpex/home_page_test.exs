defmodule Derpex.HomePageTest do
  use ExUnit.Case, async: true

  alias Derpex.HomePage
  alias Derpex.HTTP1
  alias Derpex.HTTP1.Request

  test "renders abuse, disabled, and debug sections" do
    page = HomePage.render(show_abuse_info: true, disabled: true, allow_debug: true)

    assert page =~ "If you suspect abuse"
    assert page =~ "Tailscale Security Policies"
    assert page =~ "Status:"
    assert page =~ "Debug info"
  end

  test "omits optional sections by default" do
    page = HomePage.render()
    refute page =~ "If you suspect abuse"
    refute page =~ "Status:"
    refute page =~ "Debug info"
  end

  test "serves the rendered page at the HTTP root" do
    request = %Request{
      method: "GET",
      target: "/",
      version: "HTTP/1.1",
      headers: [{"host", "derp.example"}]
    }

    assert {:response, response} =
             HTTP1.route(request, :crypto.strong_rand_bytes(32),
               home_page: [show_abuse_info: true, disabled: true, allow_debug: true]
             )

    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 200 OK"
    assert response =~ "Content-Type: text/html; charset=utf-8"
    assert response =~ "If you suspect abuse"
    assert response =~ "Status:"
    assert response =~ "Debug info"
  end
end
