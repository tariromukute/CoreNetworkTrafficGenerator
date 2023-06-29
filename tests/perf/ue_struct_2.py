import timeit
import math
import random

UEs = []

def a():
    return 2 * math.pi

def b():
    return 2 * math.pi

def c():
    return 2 * math.pi

def d():
    return 2 * math.pi

request_mapper = {
    'ar': a,
    'dr': d
}

response_mapper = {
    'as': b,
    'bs': c
}

def next_action(ue, response):
    """
    Determines the next action to process based on the given response.
    
    Args:
        response: The response received by the UE.
            Should be a string representing the current action being processed.
    
    Returns:
        The function corresponding to the action to be processed next.
    """
    # Get the action function corresponding to the given response
    action_func = response_mapper.get(response)
    
    if action_func is None:
        # Get the index of the current action in actions
        idx = ue['actions'].index(ue['action']) if ue['action'] in ue['actions'] else -1
        # Get the next action in actions (wrapping around if necessary)
        action = ue['actions'][(idx + 1) % len(ue['actions'])]
        # Get the action function corresponding to the next action
        action_func = request_mapper[action]
        # Update the UE's state with the next action
        ue['action'] = action

    # Call the action function and return its result
    return action_func()
    
def dipatcher(d):
    uid, data = d
    return next_action(UEs[uid], data)

def run():
    for u in range(1000):
        x = random.choice(['as', 'dr', 'bs'])
        dipatcher((u % 100, x))

for i in range(500):
    ue = {
        'mmn': i,
        'supi': i,
        'actions': ['ar', 'dr'],
        'action': None
    }
    UEs.append(ue)

t = timeit.Timer(setup='from __main__ import run', stmt='run()')
print(t.repeat(5, 100000))