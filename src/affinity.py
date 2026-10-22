""" CPU placement for the UE simulator and gNB processes. """


def process_cpus(num_gnbs, cpus):
    """ The CPU of each process, in start order: ueSIM-0, gnb-0, ueSIM-1, gnb-1, ...

    Each process gets a CPU of its own from the allowed set (not an index into it), so a UE simulator
    and its gNB do not share a core. The first CPU is left to the main and user plane processes while
    there are enough; with fewer CPUs than processes, the placement wraps round.
    """
    cpus = sorted(cpus)
    spare = cpus[1:] if len(cpus) > 1 else cpus
    return [spare[k % len(spare)] for k in range(2 * num_gnbs)]
