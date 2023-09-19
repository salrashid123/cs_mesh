data_dir = "data_agent_be/"
log_level = "INFO"
node_name = "node-2"
server = false,
encrypt = "EYWAIfW4DqcblgN1PLQhZWF82mHekspKkgqIBU0ef40=",


retry_join = ["10.128.0.2"]

#bind_addr = "{{ GetInterfaceIP \"ens4\" }}"
bind_addr = "0.0.0.0"
advertise_addr = "10.128.0.42"

ui_config  {
  enabled = false,
},

auto_encrypt {
  tls = true
},
tls {
  defaults {
    ca_file = "/consul/consul-agent-ca.pem",
    verify_incoming = true,
    verify_outgoing = true    
  },
}

acl {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
  tokens {
    agent  = "4de1d92f-9469-4348-09cc-4b0e4904e400"
  }
}

