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
Isolation, tool permissions and local network restrictions must be implemented
before the agent or attack phases, not assumed from this scaffold.
