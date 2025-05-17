# ebpf-stdout-tracer

Capture stdout of all processes using eBPF system call tracing.

## Install dependencies

```sh
sudo apt install bcc-tools libbcc-examples linux-headers-$(uname -r) python3-bcc
```

## Tracing

```sh
sudo python main.py
```
