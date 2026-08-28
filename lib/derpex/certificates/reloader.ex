defmodule Derpex.Certificates.Reloader do
  @moduledoc "Validates and atomically publishes rotated file-backed TLS certificates."

  use GenServer

  require Logger

  alias Derpex.Certificates
  alias Derpex.Clock

  @missing :derpex_certificate_snapshot_missing

  @doc false
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc "Returns an OTP SNI callback backed by a lock-free current snapshot."
  @spec sni_fun(term()) :: (charlist() -> keyword() | :undefined)
  def sni_fun(snapshot_key) do
    fn _server_name -> current_options(snapshot_key) end
  end

  @doc false
  @spec current_options(term()) :: keyword() | :undefined
  def current_options(snapshot_key) do
    case :persistent_term.get(snapshot_key, @missing) do
      @missing -> :undefined
      certs_keys -> [certs_keys: certs_keys]
    end
  end

  @doc "Attempts an immediate reload while retaining the last good snapshot on failure."
  @spec reload(pid()) :: {:ok, :changed | :unchanged} | {:error, term()}
  def reload(reloader), do: GenServer.call(reloader, :reload)

  @doc "Returns aggregate reload state without certificate or key material."
  @spec stats(pid()) :: map()
  def stats(reloader), do: GenServer.call(reloader, :stats)

  @impl true
  def init(options) do
    state = %{
      snapshot_key: Keyword.fetch!(options, :snapshot_key),
      certificate_path: Keyword.fetch!(options, :certificate_path),
      key_path: Keyword.fetch!(options, :key_path),
      server_public_key: Keyword.fetch!(options, :server_public_key),
      interval_ms: Keyword.get(options, :interval_ms, 60_000),
      clock: Keyword.get(options, :clock, Clock),
      digest: nil,
      timer: nil,
      reloads: 0,
      failures: 0,
      last_error: nil
    }

    with true <- is_integer(state.interval_ms) and state.interval_ms > 0,
         {:ok, :changed, state} <- load_snapshot(state) do
      {:ok, schedule(state)}
    else
      false -> {:stop, :invalid_certificate_reload_interval}
      {:error, reason, _state} -> {:stop, {:certificate_load, reason}}
    end
  end

  @impl true
  def handle_call(:reload, _from, state) do
    case load_snapshot(state) do
      {:ok, result, state} -> {:reply, {:ok, result}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:stats, _from, state) do
    stats = %{
      reloads: state.reloads,
      failures: state.failures,
      last_error: state.last_error
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:derpex_reload_certificate, state) do
    state = %{state | timer: nil}

    state =
      case load_snapshot(state) do
        {:ok, :changed, state} ->
          Logger.info("DERP TLS certificate reloaded successfully")
          state

        {:ok, :unchanged, state} ->
          state

        {:error, reason, state} ->
          Logger.warning("DERP TLS certificate reload failed: #{inspect(reason)}")
          state
      end

    {:noreply, schedule(state)}
  end

  @impl true
  def terminate(_reason, state) do
    cancel_timer(state)
    :persistent_term.erase(state.snapshot_key)
    :ok
  end

  defp load_snapshot(state) do
    with {:ok, certificate_pem} <- File.read(state.certificate_path),
         {:ok, key_pem} <- File.read(state.key_path),
         digest <- digest(certificate_pem, key_pem),
         false <- digest == state.digest,
         {:ok, certs_keys} <- build_certs_keys(certificate_pem, key_pem, state) do
      :persistent_term.put(state.snapshot_key, certs_keys)

      {:ok, :changed, %{state | digest: digest, reloads: state.reloads + 1, last_error: nil}}
    else
      true ->
        {:ok, :unchanged, state}

      {:error, reason} ->
        {:error, reason, %{state | failures: state.failures + 1, last_error: reason}}
    end
  end

  defp build_certs_keys(certificate_pem, key_pem, state) do
    options =
      Certificates.transport_options_from_pem(
        certificate_pem,
        key_pem,
        state.server_public_key
      )

    {:ok, Keyword.fetch!(options, :certs_keys)}
  rescue
    exception -> {:error, Exception.message(exception)}
  catch
    kind, reason -> {:error, Exception.format_banner(kind, reason)}
  end

  defp digest(certificate_pem, key_pem) do
    :crypto.hash(:sha256, [<<byte_size(certificate_pem)::64>>, certificate_pem, key_pem])
  end

  defp schedule(state) do
    timer = state.clock.send_after(self(), :derpex_reload_certificate, state.interval_ms)
    %{state | timer: timer}
  end

  defp cancel_timer(%{timer: timer, clock: clock}) when is_reference(timer) do
    _remaining = clock.cancel_timer(timer)
    :ok
  end

  defp cancel_timer(_state), do: :ok
end
