# Boots a real DERPEX relay inside its own OS process for the system suite.
#
# `mix run --no-start --no-halt test/system/support/relay_boot.exs` gives the
# suite a relay it can signal for real: the VM owns an OS process id, OTP's
# signal server is live, and `Derpex.Application` supervises the same tree a
# release would. Everything the test needs to talk to the relay is announced on
# a single ready line so the harness never has to guess a port or a pid.

identity_path = System.fetch_env!("DERPEX_SYSTEM_IDENTITY_PATH")
rate_config_path = System.fetch_env!("DERPEX_SYSTEM_RATE_CONFIG")

Application.put_env(:derpex, :identity_path, identity_path)
Application.put_env(:derpex, :rate_config_path, rate_config_path)
Application.put_env(:derpex, :stun_listeners, [])

Application.put_env(:derpex, :listeners, [
  [
    port: 0,
    num_acceptors: 1,
    transport_module: ThousandIsland.Transports.TCP,
    transport_options: [ip: {127, 0, 0, 1}]
  ]
])

{:ok, _started} = Application.ensure_all_started(:derpex)

[{_id, listener, _type, _modules}] = Supervisor.which_children(Derpex.ListenerSupervisor)
{:ok, {_address, listen_port}} = ThousandIsland.listener_info(listener)

IO.puts("DERPEX-SYSTEM-READY pid=#{System.pid()} port=#{listen_port}")
