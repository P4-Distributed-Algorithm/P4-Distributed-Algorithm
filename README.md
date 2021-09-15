# Distributed Message Passing Algorithm in P4

This repository contains related code of our paper "Distributed Message Passing Algorithm in P4".

## Introduction

Distributed message passing algorithms for problems such as minimum spanning tree and vertex cover have been studied for decades in the theoretical computer science community. While networking applications are often suggested as motivation, many of these algorithms have historically not been implemented in switches or other standard networking devices, because of their apparent complexity and lack of computational resources at the networked devices.

We believe the complexity calculus changes in the world of programmable switches, and that distributed message passing algorithms can now be implemented effectively. In this work we develop a general framework and an initial library of building blocks for deploying message passing algorithms on P4 switches. We start by implementing fundamental enablers such as synchronization and leader election. We then consider challenges in implementing higher-level algorithms in P4 switches, such as making them robust to packet loss and dealing with approximate arithmetic. All of our solutions run solely in the data plane, thereby allowing computation that is faster than using a centralized controller. Finally, we discuss some significant differences between the theoretical computational models and the practice of P4 switches, shedding light on the types of algorithms that can be currently implemented.

## About this repository

This repository contains our P4 library that demonstrates the essential primitives of our P4 message passing framework with four message passing algorithms (leader election, MST, vertex cover, MIS) as examples. All the related code can be found at `./src_p4`. We also open-source our code of the original CPU version at `./src_CPU`.

## Requirements

Our experiments is conducted on an Ubuntu 18.04 LTS server. Besides, here are the dependencies:

- mininet == 2.3.0

- p4c == 1.2.0+g202103291035~a69e52 (https://github.com/p4lang/p4c.git)

- behavioral model (https://github.com/p4lang/behavioral-model.git)

- p4-utils (https://github.com/nsg-ethz/p4-utils.git)

python modules:

- scapy == 2.4.4

## Running experiments of the CPU version

1. Configure the topology of the network, and launch the mininet to create a virtual network:

- In `./src_CPU/topo/topology.json`, first we configure the topology of the network and specify properties for each link (delay, bandwidth in Mbits, queue_length, etc). `./src_CPU/topo/topology.json` shows an example to configure the topology. We also provide a helper script `./src_CPU/topo/gen_topology.py` to automatically generate a 3-layer fat tree topology. You can simply run: `python gen_topology.py --k_port {K_PORT} --loss_rate {LOSS_RATE(%)} --base_delay {BASE_DELAY (ms)}`.

- After that, simply run `python launch_mininet.py` to create a virtual network with topology configured as `topology.json`. Use Ctrl + D to distroy the virtual network and exit.

2. Running your distributed algorithm on our framework.

- In `./src_CPU`, first we run `bash config.sh` to obtain the process id for each node of the virtual network. The process id will be used to enable the threads of the program to attach to the corresponding virtual hosts / switches.

- For the Boruvka's algorithm and the vertex cover algorithm, we generate the weights for edges or nodes. Run `python boruvka_weight_gen.py` or `python vertex_weight_gen.py`.

- Then we simply run `python launch.py --program {YOUR_PROGRAM} --benchmark_file {PREFERRED_FILE_FOR_BENCHMARK}` to launch the program and simulate the experiments.

## Running experiments of the P4 version

Before running the experiments, make sure you have installed p4-util tools `https://github.com/nsg-ethz/p4-utils`.

In `./src_p4`, we provide our P4 implementation of four distributed algorithm. The `p4src_simple` contains the main primitives of the P4 program, and `scripts` folder provides the controller primitive and utility tools for running the experiments.

1. Configure the topology of the network.

- For the P4 version, we can configure the topology in `p4app.json` the same way as that for the CPU version. To mimic the packet generator and the real data traffic, we simply add hosts `h{i}` and a link (`h{i}`, `s{i}`), so that we no longer need to route for the real data traffic. 

- You could further specify other configurations apart from the topology. For example, we can set `enable_log` as true to enable switches' log.

- In `./src_p4/helper/gen_topology.py`, we also provide a script to generate a fat tree automatically.

- After configuring the topology, make sure you modify the `SINGLE_HOP_DELAY` in the P4 program. The `SINGLE_HOP_DELAY` should be slightly larger than the link delay in $\mu$s.

2. Launching the virtual network and all the P4 switches.

- In `./src_p4/{experiment}/p4src_simple`, simply run `sudo p4run`. After that, the virtual network and all the P4 switches will be set up.

3. Loading initial configurations to the P4 switches.

- In `./src_p4/{experiment}/scripts`, run `sudo python routing_controller.py`. This program load all the initial configuration (initial values of the registers and values of the match-action tables) into all the P4 switches. Note that our framework does not need runtime configurations.

4. Launching packet sniffers to display the packets.

- In `./src_p4/{experiment}scripts`, run `sudo python packet_monitor.py` to monitor the packets.

5. (Optional) Sending data packets for simulating real traffic and handling packet loss.

- Run `python launch_data_pkt_sim.py` if you set the loss rate as a non-zero value. This program aims for handling loss of packets.

6. Launching the packet generator to run the distributed program.

- The P4 program is designed so that it starts the distributed program if it receives an "event" packet. In `./src_p4/{experiment}/scripts`, run `sudo python pkt_generator.py` to inject the event packet to start the whole framework. The whole network will start to work until it converges. You can monitor the packets as well as the time the network stops via `packet_monitor.py`.

6. (Optional) Inspecting the values of the registers to debug.

- In `./src_p4/scripts`, run `python register_reader.py --sw_name {all/TARGET_SWITCH} --reg_name {TARGET_REGISTER}` to inspect the values of the registers in P4 switches.

**Note**:
1. You should create a folder `switch_log` in `./src_p4/{experiment}/` the first time you run.

2. Run the program in sudo whenver we need the sudo privilege.


