# Project 2: Intra-Domain Routing Algorithms

## Objective

* Implement distance-vector or link-state routing algorithms

## Getting Started

To start this project, you will first need to get the [infrastructure setup](https://github.com/minlanyu/cs145-site/blob/spring2025/infra.md) and clone this repository with submodules

```bash
git clone --recurse-submodules "<your repository>"
```

When there are updates to the starter code, TFs will open pull requests in your repository. You should merge the pull request and pull the changes back to local. You might need to resolve conflicts manually (either when merging PR in remote or pulling back to local). However, most of the times there shouldn't be too much conflict as long as you do not make changes to test scripts, infrastructures, etc. Reach out to TF if it is hard to merge.

## Introduction

The Internet is composed of many independent networks (called autonomous systems) that must cooperate in order for packets to reach their destinations. This necessitates different protocols and algorithms for routing packet within autonomous systems, where all routers are operated by the same entity, and between autonomous systems, where business agreements and other policy considerations affect routing decisions.

This project focuses on intra-domain routing algorithms used by routers within a single autonomous system (AS). The goal of intra-domain routing is typically to forward packets along the shortest or lowest cost path through the network.

The need to rapidly handle unexpected router or link failures, changing link costs (usually depending on traffic volume), and connections from new routers and clients, motivates the use of distributed algorithms for intra-domain routing. In these distributed algorithms, routers start with only their local state and must communicate with each other to learn lowest cost paths.

Nearly all intra-domain routing algorithms used in real-world networks fall into one of two categories, distance-vector or link-state. In this project, you will implement distributed distance-vector and link-state routing algorithms in Python and test them with a provided network simulator.

> [!NOTE]
> You are only required to implement either distance-vector or link-state. If you implement both, you can get a bonus of 20 points.
>
> You will do this project in the same VM as previous project.

## Background

At a high level, they work as follows. Your goal in this project is to turn this high-level description to actual working code. You might find it helpful to review the details of the algorithms in textbooks (see course syllabus for textbook recommendations).

### Distance-Vector Routing

* Each router keeps its own distance vector, which contains its distance to all destinations.
* When a router receives a distance vector from a neighbor, it updates its own distance vector and the forwarding table.
* Each router broadcasts its own distance vector to all neighbors when the distance vector changes. The broadcast is also done periodically if no detected change has occurred.
* Each router **does not** broadcast the received distance vector to its neighbors. It **only** broadcasts its own distance vector to its neighbors.

### Link-State Routing

* Each router keeps its own link state and other nodes' link states it receives. The link state of a router contains the links and their weights between the router and its neighbors.
* When a router receives a link state from its neighbor, it updates the stored link state and the forwarding table. **Then it broadcasts the link state to other neighbors.**
* Each router broadcast its own link state to all neighbors when the link state changes. The broadcast is also done periodically if no detected change has occurred.
* A sequence number is added to each link state message to distinguish between old and new link state messages. Each router stores the sequence number together with the link state. If a router receives a link state message with a smaller sequence number (i.e., an old link state message), the link state message is simple disregarded.

## Provided code

### Familiarize yourself with the network simulator

The provided code implements a network simulator that abstracts away many details of a real network, allowing you to focus on intra-domain routing algorithms. Each `.json` file in this directory is the specification for a different network simulation with different numbers of routers, links, and link costs. Some of these simulations also contain link additions and/or failures that will occur at pre-specified times.

The network simulator can run with or without a graphical interface. For example, the command

```bash
python visualize_network.py 01_small_net.json
```

will run the simulator on a simple network with 2 routers and 3 clients. The default router implementation returns all traffic back out the link on which it arrives. This is obviously a terrible routing algorithm, which your implementations will fix.

The network architecture is shown on the left side of the visualization. Routers are colored red, clients are colored blue. Each client periodically sends gray traceroute-like packets addressed to every other client in the network. These packets remember the sequence of routers they traverse, and the most recent route taken to each client is printed in the text box on the top right. This is an important debugging tool.

The cost of each link is printed on the connections.

Clicking on a client hides all packets except those addressed to that client, so you can see the path chosen by the routers. Clicking on the client again will go back to showing all packets.

Clicking on a router causes a string about that router to print in the text box on the lower right. You will be able to set the contents of this string for debugging your router implementations.

The same network simulation can be run without the graphical interface by the command following command:

```bash
python network.py 01_small_net.json
```

The simulation will run faster without having to go at visualizable speed. It will stop after a predetermined amount of time, print the final routes taken by the traceroute packets to and from all clients and whether these routes are correct given the known lowest-cost paths through the network.

## Implementation Instructions

Your job is to complete the `DVrouter` and `LSrouter` classes in the `DVrouter.py` and `LSrouter.py` files so they implement distance-vector or link-state routing algorithms, respectively. The simulator will run independent instances of your completed `DVrouter` or `LSrouter` classes in separate threads, simulating independent routers in a network.

You will notice that the `DVrouter` and `LSrouter` classes contain several unfinished methods marked with `TODO`. They are:

- `__init__`
- `handle_packet`
- `handle_new_link`
- `handle_remove_link`
- `handle_time`
- `__repr__` (optional, for your own debugging)

These methods override those in the `Router` base class (in `router.py`) and are called by the simulator when a corresponding event occurs (e.g. `handle_packet` will be called when a router instance receives a packet).

> [!NOTE]
> Check the docstrings of corresponding methods in the `Router` base class in `router.py` for detailed descriptions.

In addition to completing each of these methods, you are free to add additional fields (instance variables) or helper methods to the `DVrouter` and `LSrouter` classes.

You will be graded on whether your solutions find lowest cost paths in the face of link failures and additions. Here are a few further simplifications:

* Each client and router in the network simulation has a single static address. Do not worry about address prefixes, families, or masks.
* You do not need to worry about packet authentication and checksums. Assume that a lower layer protocol handles corruption checking.
* As long your routers behave correctly when notified of link additions and failures, you do not need to worry about time-to-live (TTL) fields. The network simulations are short and routers/links will not fail silently.
* The slides discuss the "count-to-infinity" problem for distance-vector routing. You will need to handle this problem. You can use the heuristic discussed in the slides. Setting infinity = 16 is fine for the networks in this project.
* Link-state routing involves reliably flooding link state updates. You will need to use **sequence numbers** to distinguish new updates from old updates, but you will not need to check (via acknowledgements and retransmissions) that LSPs send successfully between adjacent routers. Assume that a lower-level protocol makes single-hop sends reliable.
* Link-state routing involves computing shortest paths. You can choose to implement Dijkstra's algorithm, and the pseudo code is in the slides. Since this is a networking class instead of a data structures and algorithms class, you can also use a Python package like [NetworkX](https://networkx.org/).
* Finally, LS and DV routing involve periodically sending routing information even if no detected change has occurred. This allows changes occurring far away in the network to propagate even if some routers do not change their routing tables in response to these changes (important for this project). It also allows detection of silent router failures (not tested in this project). You implementations should send periodic routing packets every `heartbeat_time` milliseconds where `heartbeat_time` is an argument to the `DVrouter` or `LSrouter` constructor. You will regularly get the current time in milliseconds as an argument to the `handle_time` method (see below).

### Restrictions

There are limitations on what information your `DVrouter` and `LSrouter` classes are allowed to access from the other provided Python files. Unlike C and Java, Python does not support private variables and classes. Instead, the list of limitations here will be checked when grading. Violating any of these requirements will result in serious grade penalties.

* Your solution must not require modification to any files other than `DVrouter.py` and `LSrouter.py`. The grading tests will be performed with unchanged versions of the other files.

* Your code may not call any functions or methods, instantiate any classes, or access any variables defined in any of the other provided Python files, with the following exceptions:
  * `LSrouter` and `DVrouter` can call the inherited `send` function of the `Router` base class (e.g. `self.send(port, packet)`).
  * `LSrouter` and `DVrouter` can access the `addr` field of the `Router` base class (e.g. `self.addr`) to get their own address.
  * `LSrouter` and `DVrouter` can create new `Packet` objects and call any of the methods defined in `packet.py` **EXCEPT FOR** `add_to_route` and `animate_send`. You can access and change any of the fields of a `Packet` object **EXCEPT FOR** `route`.

### Creating and sending packets

You will need to create packets to send information between routers using the `Packet` class defined in `packet.py`. Any packet `p` you create to send routing information should have `p.kind == Packet.ROUTING`.

You will have to decide what to include in the `content` field of these packets. The content should be reasonable for the algorithm you are implementing (e.g. don't send an entire routing table for link-state routing).

Packet content must be a string. This is checked by an assert statement when the packet is sent. `DVrouter` and `LSrouter` uses the `dumps` and `loads` functions from the built-in library `json` which provide an easy way to stringify and de-stringify Python objects.

You can access and set/modify any of the fields of a packet object (including `content`, `src_addr`, `dst_addr`, and `kind`) except for `route` (see [Restrictions](#restrictions) above).

### Link reliability

If a link between two routers fails or is added, the appropriate `handle` function will *always* be called on both routers after the failure or addition.

Links have varying latencies (usually proportional to their costs). Packets may not arrive in the global order that they are sent.

### Ceci n'est pas un network...

The simulated network in this project abstracts away many details you would need to consider when implementing distance-vector or link-state algorithms on real routers. This should allow you to focus on the core ideas of the algorithms without worrying about other protocols (e.g. ARP) or meticulous systems programming issues. If you are curious about these real-world details, please ask on discussion forum or in office hours.

## Running and Testing

You should test your `DVrouter` and `LSrouter` using the provided network simulator. There are multiple JSON files defining different network architectures and link failures and additions. The JSON files without `_events` in their file name do not have link failures or additions and are good for initial testing.

To run the simulation with a graphical interface:

```
usage: visualize_network.py [-h] net_json_path [{DV,LS}]

Visualize a network simulation.

positional arguments:
  net_json_path  Path to the network simulation configuration file (JSON).
  {DV,LS}        DV for DVrouter and LS for LSrouter. If not provided, Router is used.

options:
  -h, --help     show this help message and exit
```

The second argument can be `DV` or `LS` which indicates whether to run `DVrouter` or `LSrouter`, respectively.

To run the simulation without the graphical interface:

```
usage: network.py [-h] net_json_path [{DV,LS}]

Run a network simulation.

positional arguments:
  net_json_path  Path to the network simulation configuration file (JSON).
  {DV,LS}        DV for DVrouter and LS for LSrouter. If not provided, Router is used.

options:
  -h, --help     show this help message and exit
```

The routes to and from each client at the end of the simulation will print, along with whether they match the reference lowest-cost routes. If the routes match, your implementation has passed for that simulation. If they do not, continue debugging (using print statements and the `__repr__` method in your router classes).

The bash script `test_scripts/test_dv_ls.sh` will run all the supplied networks with your router implementations. You can also pass `LS` or `DV` as an argument to `test_scripts/test_dv_ls.sh` (e.g. `./test_scripts/test_dv_ls.sh DV`) to test only one of the two implementations.

Don't worry if you get the following error. It sometimes occurs when the threads are stopped at the end of the simulation without warning:

```
Unhandled exception in thread started by
sys.excepthook is missing
lost sys.stderr
```

> [!TIP]
> [Here](https://docs.google.com/presentation/d/1fMRK9q8kwFetMDZPQaZFmzvQeFDklqAXN8QJOwidEHg/edit?usp=sharing) are the project section slides from previous year -- you may find them useful!

## Submission and Grading

### Submit your work

You are expected to tag the version you would like us to grade on using following commands and push it to your own repo. You can learn from [this tutorial](https://git-scm.com/book/en/v2/Git-Basics-Tagging) on how to use git tag command. This command will record the time of your submission for our grading purpose.

```bash
git tag -a submission -m "Final Submission"
git push --tags
```

### What to submit

You are expected to submit the following documents:

1. The source code for `DVrouter.py` or `LSrouter.py`.
2. Bonus: If you submit both `DVrouter.py` and `LSrouter.py` and they pass all the tests, you can get a bonus of 20 points.

We will run the network simulation using the provided JSON files. Your grade will be based on whether your algorithm finds the lowest cost paths and whether you have violated any of the restrictions listed above. We will also check that `DVrouter` actually runs a distance-vector algorithm and that `LSrouter` actually runs a link-state algorithm.

### Grading

The total grades is 100:

- 30: correctness of code
  - 10: doesn't modify files other than `DVrouter.py` and `LSrouter.py`
  - 10: doesn't use restricted functions and variables in provided files (see [Restrictions](#restrictions))
  - 10: algorithmic correctness
- 20: passing two small_net tests (10 for each)
- 30: passing two pg244_net tests (15 for each)
- 20: passing two pg242_net tests (10 for each)
- 20: bonus points for implementing both (and passing all tests)
- Deductions based on late policies
- For this project, you are not required to modify the report (but please feel free to include citations and grading notes there).

## Acknowledgements

This programming project is based on Princeton University's Project 2 from COS 461: Computer Networks, and Johns Hopkins University's Assignment 3 from EN.601.414/614: Computer Networks.

## Survey

Please fill up the survey when you finish your project: [Survey link](https://forms.gle/jfeQDjfNHbMTqPfT7).
