import timeit
import math

IE = {'id': 1, 'criticality': 'reject', 'value': ('GlobalRANNodeID', ('globalGNB-ID', {'gNB-ID': ('gNB-ID', (1, 32))}))}

# Function A
def a(IEs):
    IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
    return IEs[0]['id'] * 2 * math.pi

# Function B
def b(IEs):
    IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'UERANSIM-gnb-208-95-1')})
    return IEs[0]['id'] * 2 * math.pi

class Test:

    def __init__(self) -> None:
        self.dispatcher = {
            0: a,
            1: b
        }
    
    def select(self, k):
        IEs = [] # Passing by reference here reduces the time
        IEs.append(IE)
        return self.dispatcher[k](IEs)

    
    def run(self):
        for i in range(100):
            self.select(i % 2)

a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())

