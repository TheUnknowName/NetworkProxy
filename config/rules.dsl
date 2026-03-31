# Rule DSL sample
# Syntax:
# rule "name" {
#   when.protocol = tcp|udp|http|https|any
#   when.direction = inbound|outbound|any
#   when.host_contains = example.com
#   when.method = POST
#   when.path_contains = /api
#   when.remote_port = 443
#   action.text_find = hello
#   action.text_replace = patched_hello
#   action.hex_find = 68656c6c6f
#   action.hex_replace = 776f726c64
#   action.body_find = old
#   action.body_replace = new
#   action.header_set.X-Trace-Id = debug-123
# }

rule "tcp-outbound-demo" {
  when.protocol = tcp
  when.direction = outbound
  action.text_find = hello
  action.text_replace = patched_hello
}

rule "udp-inbound-demo" {
  when.protocol = udp
  when.direction = inbound
  action.text_find = world
  action.text_replace = patched_world
}

rule "http-request-header-demo" {
  when.protocol = http
  when.direction = outbound
  when.method = post
  when.path_contains = /api
  action.header_set.X-Trace-Id = dsl-trace
}
