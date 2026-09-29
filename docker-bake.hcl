group "validate" {
  targets = [
    "build-report",
    "node",
    "validator",
    "note-transport",
    "ntx-builder",
    "remote-prover",
    "network-monitor",
    "funding-service",
    "node-tps-benchmark",
    "usdcx-genesis",
  ]
}

target "common" {
  context    = "."
  dockerfile = "Dockerfile"
}

target "build-report" {
  inherits = ["common"]
  target   = "build-report"
  output   = ["type=local,dest=./kache-report"]
}

target "node" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-node"
    PORT = "57291"
  }
}

target "validator" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-validator"
    PORT = "50101"
  }
}

target "note-transport" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-note-transport"
    PORT = "57292"
  }
}

target "ntx-builder" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-ntx-builder"
    PORT = "50301"
  }
}

target "remote-prover" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-remote-prover"
    PORT = "50051"
  }
}

target "network-monitor" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-network-monitor"
    PORT = "3000"
  }
}

target "funding-service" {
  inherits = ["common"]
  target   = "runtime"
  args = {
    BIN  = "miden-funding-service"
    PORT = "50401"
  }
}

target "node-tps-benchmark" {
  inherits = ["common"]
  target   = "runtime-tool"
  args = {
    BIN = "miden-benchmark"
  }
}

target "usdcx-genesis" {
  inherits = ["common"]
  target   = "runtime-tool"
  args = {
    BIN = "xusdc-genesis"
  }
}
