import timeit
import math
import random

ues = []

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

class UE:
    def __init__(self, config):
        """
        Initializes a new UE object with the given configuration.
        
        Args:
            config (dict): A dictionary containing the configuration data for the UE.
                Must have the keys 'mmn' and 'supi'.
        
        Returns:
            None
        """
        if 'mmn' not in config or 'supi' not in config:
            raise ValueError("Invalid configuration data: missing keys 'mmn' or 'supi'")
        self.id = "mmn{}".format(config['mmn'])
        self.supi = config['supi']
        self.actions = ['ar', 'dr']
        self.action = None # contains the request that UE is processing or has 
        self.processing = False # states where the UE has sent a reponse
        self.state = 'IDLE'

    def next_action(self, response):
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
            idx = self.actions.index(self.action) if self.action in self.actions else -1
            # Get the next action in actions (wrapping around if necessary)
            action = self.actions[(idx + 1) % len(self.actions)]
            # Get the action function corresponding to the next action
            action_func = request_mapper[action]
            # Update the UE's state with the next action
            self.action = action
    
        # Call the action function and return its result
        return action_func()
    
def dipatcher(d):
    uid, data = d
    return ues[uid].next_action(data)

def run():
    for u in range(1000):
        x = random.choice(['as', 'dr', 'bs'])
        dipatcher((u % 100, x))

for i in range(500):
    config = {
        'mmn': i,
        'supi': i,
        'actions': ['ar', 'dr']
    }
    ues.append(UE(config))

t = timeit.Timer(setup='from __main__ import run', stmt='run()')
print(t.repeat(5, 100000))