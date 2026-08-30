defmodule Derpex.HTTP1.Response do
  @moduledoc false

  @status_reasons %{
    200 => "OK",
    204 => "No Content",
    302 => "Found",
    400 => "Bad Request",
    401 => "Unauthorized",
    403 => "Forbidden",
    404 => "Not Found",
    405 => "Method Not Allowed",
    426 => "Upgrade Required",
    500 => "Internal Server Error",
    503 => "Service Unavailable"
  }

  @spec encode(non_neg_integer(), [{binary(), binary()}], iodata()) :: iodata()
  def encode(status, headers, body \\ "") do
    body_length = IO.iodata_length(body)

    headers =
      if body_length > 0 and not List.keymember?(headers, "Content-Length", 0) do
        headers ++ [{"Content-Length", Integer.to_string(body_length)}]
      else
        headers
      end

    reason = Map.fetch!(@status_reasons, status)
    encoded_headers = Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end)
    ["HTTP/1.1 ", Integer.to_string(status), " ", reason, "\r\n", encoded_headers, "\r\n", body]
  end
end
