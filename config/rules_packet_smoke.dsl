rule "tcp-text-outbound" {
  when.protocol = tcp
  when.direction = outbound
  action.text_find = hello
  action.text_replace = patched_hello
}

rule "tcp-text-inbound" {
  when.protocol = tcp
  when.direction = inbound
  action.text_find = world
  action.text_replace = patched_world
}

rule "udp-text-outbound" {
  when.protocol = udp
  when.direction = outbound
  action.text_find = hello
  action.text_replace = patched_hello
}

rule "udp-text-inbound" {
  when.protocol = udp
  when.direction = inbound
  action.text_find = world
  action.text_replace = patched_world
}

rule "tcp-binary-outbound" {
  when.protocol = tcp
  when.direction = outbound
  when.remote_port = 29080
  action.hex_find = 0102
  action.hex_replace = 0A0B
}

rule "tcp-binary-inbound" {
  when.protocol = tcp
  when.direction = inbound
  when.remote_port = 29080
  action.hex_find = 0A0B
  action.hex_replace = C0D0
}

rule "http-header-outbound" {
  when.protocol = http
  when.direction = outbound
  when.method = post
  when.path_contains = /api
  action.header_set.X-Smoke = dsl-smoke
}

rule "http-body-inbound" {
  when.protocol = http
  when.direction = inbound
  action.body_find = world
  action.body_replace = patched_world
}
