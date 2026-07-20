XDR- Correlator

Overview
XDR-Correlator is a cross-layer intrusion detection system that correlates sugnals from network packet inpection, host filesystem activity, and kernel-level eBPF hooks into a single, unified stream of security alerts. It watches for complete attack signatures like shellcode staging patterns in TCP payloads, SCTP INIT floods, TCP sequence-number hijacking, suspicious file drops, and unauthorized eBPF program loads. It correlates these across a sliding time window to flag multi-stage attack sequences rather than isolated alerts. These events are live streamed to a web dashboard over WebSockets to view detections and incident reports appear in real time as traffic is replayed or captured

Architecture
┌──────────────────────────── DETECTION LAYER ────────────────────────────┐
 │                                                                          │
 │   NETWORK VECTOR              BINARY VECTOR           KERNEL VECTOR     │
 │  ┌──────────────────┐       ┌──────────────────┐    ┌─────────────────┐│
 │  │ PcapInvestigator │       │ XdrFileWatchdog  │    │ BpfSyscallWatcher││
 │  │  - payload_scan  │       │  (watchdog       │    │  (BCC kprobe on ││
 │  │    (NOP sled,    │       │   Observer       │    │   __sys_bpf)    ││
 │  │    repeat-byte,  │       │   thread)        │    │                 ││
 │  │    GOT pointer)  │       │                  │    │  runs in a      ││
 │  │ SctpFloodDetector│       │  create/modify/  │    │  background     ││
 │  │ TcpHijackDetector│       │  delete/move     │    │  polling thread ││
 │  └────────┬─────────┘       └────────┬─────────┘    └────────┬────────┘│
 │           │                          │                        │        │
 └───────────┼──────────────────────────┼────────────────────────┼────────┘
             │                          │                        │
             │   ENGINE.publish_threadsafe(SecurityEvent)         │
             └──────────────────────────┼────────────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │   CorrelationEngine (asyncio)  │
                         │   xdr/core/event_bus.py        │
                         │   - asyncio.Queue, thread-safe  │
                         │     publish via                │
                         │     call_soon_threadsafe()      │
                         └───────────────┬─────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │   KillChainCorrelator          │
                         │   xdr/correlation/             │
                         │   - sliding window per src      │
                         │     (default 300s)             │
                         │   - stage_map.py translates     │
                         │     real event_types ->         │
                         │     recon/exploit/persist       │
                         │   - escalates to JSON incident  │
                         │     report on full 3-stage match│
                         └───────────────┬─────────────────┘
                                         ▼
                         ┌───────────────────────────────┐
                         │   FastAPI dashboard (api/)     │
                         │   - GET /        (HTML client) │
                         │   - WS  /ws      (broadcasts    │
                         │     every SecurityEvent + any   │
                         │     incident report as JSON)    │
                         └───────────────┬─────────────────┘
                                         ▼
                              Browser (index.html)
                       color-coded live-scrolling alert feed

xdr/correlator.py (XDRCorrelator) owns the network side detectors and drives them from a pcap file or live capture
xdr/binary/elf_analyzer.py (ElfParser) is used at startup separate from above to parse target binary's .got/ .got.plt address range and passes it to payload_scan.scan_payload() for GOT-pointer detection to be binded to a real binary

Setup
Used Ubuntu with CONFIG_KPROBES=y in the runnning kernel for eBPF hook

#system packages
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc bpftool linux-headers-generic

#project dependencies
python3 -m venv venv
source venv/bin/activate
pip install scapy pytestwatchdog fastapi uvicorn websockets

How to run
Run teh test suite:
PYTHONPATH =. pytest tests/ -v

Replay a pcap through the ful stack with the live dashbaord:
python3 main.py testdata/pcaps/05_combo_exploit.pcap

This starts the FastAPI dashboard in the background and waits for the browser to open the localhost before replaying the pcap since there is no history buffer

Run the host-sdie monitors (file watchdog + eBPF hook) concurrently;
sudo python3 run_host_monitors.py --watch-dir /tmp/xdr_watch_test

Requires root permission

Run the benchmark suite (See Results):
PYTHONPATH=. python3 benchmarks/run_benchmarks.py

Benchmark results
Measured with above on Ubuntu 26.04 LTS under WSL2, kernel 6.6.87.2-microsoft-standard-WSL2

Detection Latency
this is from time.perf_counter() handing packet to the detectors, to the resultsing SecuritEvent landing in CorrelationEngine
Attack pcap	        Events measured  Mean	    Median	    p95	        Min / Max
NOP sled	        3	             0.843 ms	0.845 ms	0.849 ms	0.835 / 0.849 ms
Repeated-byte pad	2	             0.708 ms   0.708 ms	0.710 ms	0.706 / 0.710 ms
GOT pointer	        1	             0.525 ms   0.525 ms	0.525 ms	0.525 / 0.525 ms
Combo exploit	    3	             0.445 ms	0.445 ms	0.447 ms	0.442 / 0.447 ms
SCTP INIT flood	    6	             0.203 ms	0.192 ms    0.274 ms	0.158 / 0.274 ms
TCP hijack	        1	             0.383 ms	0.383 ms	0.383 ms	0.383 / 0.383 ms

All latencies are in sub-milliseconds. This measures in-process Python latency only (packet handed to detector -> event queued) not Live capture.

False-positive rate
Replayed a 600-packet benign-only pcap (testdata/pcap/08_benign_web_traffic.pcap is 60 complete simulated HTTP sessions: TCP Handshake, GET/POST request, response, graceful close) through the full detector stack

Metric	            Value
Total packets	    600
False positives	    0
FP rate	            0.0%

Maximum throughput
Measurement	                                                Result
Raw max speed (unpaced, single detector thread,             4,394.4 packets/sec
no concurrent consumer)	    
Sustained rate with a concurrent async consumer             1,370.7 packets/sec
draining the queue	
Queue backlog growth under 3s sustained load at             None observed as queue depth 
that rate	                                                stayed at 0 throughout

The drop from approximately 4,400 ppsto around 1,370 pps when a conumer task runs concurrently is real asyncio task-switching overhead between the producer (detector loop) and consumer (queue-draining coroutine) sharing one event loop under WSL2. No backlog growth was observed at the sustained rate, meaning the consumer keeps up indefinitely at that throughput in this environment.

Limitations
    - KillChainCorrelator correlates events by exact src string equality. Network events use an IP, file events use a path, and eBPF events use a pid=X comm=Y string which all naturally not match with src so a kill chain spanning all three vectors will not currently auto-correlate without a shared asset-identity scheme
    - There is no event history buffer, only broadcast after browser connects