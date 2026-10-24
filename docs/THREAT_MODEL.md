# Threat model (initial scope)

A tool-using agent reads untrusted task material. The attacker controls injected
file, page, or tool-output content, not the monitor or kernel. The defender owns
the disposable VM, agent workspace, fake canaries and local HTTP sinks. Later
adaptive experiments disclose detector features and thresholds to the attacker.

Protected outcomes include task fidelity and keeping canaries and writes within
the intended task scope. The monitor observes OS metadata, not semantic intent.
A valid-looking poisoned summary may have no distinguishing OS footprint; this
is a hypothesis to measure, not an established result.

No real credentials, host mounts, external targets, scanning, or paid APIs.
A cgroup selects trace subjects; it is not by itself a security sandbox. A
container also shares its kernel; the VM provides the outer disposal boundary.

The benign and injection runners reset UFW inside the throwaway VM to deny all
incoming, routed, and outgoing traffic, with explicit inbound and outbound
allow rules on `lo` only. This runs after runtime/model installation so Ollama
can serve locally while the agent and its shell tools cannot reach external
hosts. The fixture sink also binds only to `127.0.0.1`. If the guest cannot
confirm this policy, the runner fails before starting the agent. The firewall
change is confined to the disposable guest; do not run the lockdown script on a
host or a VM that contains unrelated workloads.
